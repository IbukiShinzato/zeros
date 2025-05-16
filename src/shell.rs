use crate::helper::DynError;
use nix::{
    libc,
    sys::{
        signal::{SigHandler, Signal, killpg, signal},
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::{self, ForkResult, Pid, dup2, execvp, fork, pipe, setpgid, tcgetpgrp, tcsetpgrp},
};
use rustyline::{Editor, error::ReadlineError};
use signal_hook::{consts::*, iterator::Signals};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    ffi::CString,
    mem::replace,
    process::exit,
    sync::mpsc::{Receiver, Sender, SyncSender, channel, sync_channel},
    thread,
};

/// システムコール呼び出しのラッパ。EINTR（割り込みによって中断されたシステムコール） ならリトライ。
fn syscall<F, T>(f: F) -> Result<T, nix::Error>
where
    F: Fn() -> Result<T, nix::Error>,
{
    loop {
        match f() {
            Err(nix::Error::EINTR) => (),
            result => return result,
        }
    }
}

/// workerスレッドが受信するメッセージ
enum WorkerMsg {
    Signal(i32), // シグナルを受信
    Cmd(String), // コマンド入力
}

/// mainスレッドが受信するメッセージ
enum ShellMsg {
    Continue(i32), // シェルの読み込みを再開。i32は最後の終了コード
    Quit(i32),     // シェルを終了。i32はシェルの終了コード
}

#[derive(Debug)]
pub struct Shell {
    logfile: String, // ログファイル
}

impl Shell {
    pub fn new(logfile: &str) -> Self {
        Shell {
            logfile: logfile.to_string(),
        }
    }

    /// mainスレッド。
    pub fn run(&self) -> Result<(), DynError> {
        // SIGTTOUを無視に設定しないと、SIGTSTP(Ctrl + Z)が配送される。
        unsafe { signal(Signal::SIGTTOU, SigHandler::SigIgn).unwrap() };

        let mut rl = Editor::<()>::new()?;
        if let Err(e) = rl.load_history(&self.logfile) {
            eprintln!("ZeroSh: ヒストリファイルの読み込みに失敗: {}", e);
        };

        // チャネルを生成し、signal_handlerとworkerスレッドを生成
        let (worker_tx, worker_rx) = channel();
        let (shell_tx, shell_rx) = sync_channel(0);
        spawn_sig_handler(worker_tx.clone())?;
        Worker::new().spawn(worker_rx, shell_tx);

        let exit_val; // 終了コード
        let mut prev = 0; // 直前の終了コード
        loop {
            // 1行読み込んで、その行をworkerスレッドに送信
            let face = if prev == 0 { '\u{1F982}' } else { '\u{1F4A9}' };
            match rl.readline(&format!("ZeroSh {} %> ", face)) {
                Ok(line) => {
                    let line_trimed = line.trim(); // 行頭と行まつの空白文字を削除
                    if line_trimed.is_empty() {
                        continue; // 空のコマンドの場合は再読み込み
                    } else {
                        rl.add_history_entry(line_trimed); // ヒストリファイルに追加
                    }

                    // workerスレッドに送信
                    worker_tx.send(WorkerMsg::Cmd(line)).unwrap();
                    match shell_rx.recv().unwrap() {
                        ShellMsg::Continue(n) => prev = n, // 読み込み再開
                        ShellMsg::Quit(n) => {
                            // シェルを終了
                            exit_val = n;
                            break;
                        }
                    }
                }
                Err(ReadlineError::Interrupted) => eprintln!("ZeroSh: 終了はCtrl+d"),
                Err(ReadlineError::Eof) => {
                    worker_tx.send(WorkerMsg::Cmd("exit".to_string())).unwrap();
                    match shell_rx.recv().unwrap() {
                        ShellMsg::Quit(n) => {
                            // シェルを終了
                            exit_val = n;
                            break;
                        }
                        _ => panic!("exitに失敗"),
                    }
                }
                Err(e) => {
                    eprintln!("ZeroSh: 読み込みエラー\n{}", e);
                    exit_val = 1;
                    break;
                }
            }
        }

        if let Err(e) = rl.save_history(&self.logfile) {
            eprintln!("ZeroSh: ヒストリファイルへの書き込みに失敗: {}", e);
        };
        exit(exit_val);
    }
}

/// signal_handlerスレッド
fn spawn_sig_handler(tx: Sender<WorkerMsg>) -> Result<(), DynError> {
    let mut signals = Signals::new(&[SIGINT, SIGTSTP, SIGCHLD])?;
    thread::spawn(move || {
        for sig in signals.forever() {
            // シグナルを受信しworkerスレッドに転送
            tx.send(WorkerMsg::Signal(sig)).unwrap();
        }
    });

    Ok(())
}

#[derive(Debug, PartialEq, Eq, Clone)]
enum ProcState {
    Run,  // 実行中
    Stop, // 停止中
}

#[derive(Debug, Clone)]
struct ProcInfo {
    state: ProcState, // 実行状態
    pgid: Pid,        // プロセスグループID
}

#[derive(Debug)]
struct Worker {
    exit_val: i32,   // 終了コード
    fg: Option<Pid>, // フォアグラウンドのプロセスグループID

    // ジョブIDから（プロセスグループID, 実行コマンド）へのマップ
    jobs: BTreeMap<usize, (Pid, String)>,

    // プロセスグループIDから（ジョブID, プロセスID）へのマップ
    pgid_to_pids: HashMap<Pid, (usize, HashSet<Pid>)>,

    pid_to_info: HashMap<Pid, ProcInfo>, // プロセスIDからプロセスグループIDへのマップ
    shell_pgid: Pid,                     // シェルのプロセスグループID
}

impl Worker {
    fn new() -> Self {
        Worker {
            exit_val: 0,
            fg: None, // フォアグラウンドはシェル
            jobs: BTreeMap::new(),
            pgid_to_pids: HashMap::new(),
            pid_to_info: HashMap::new(),

            // シェルのプロセスグループIDを取得
            // tcgetpgrpを使用することによってshellがフォアグラウンドであるかも検査できる
            shell_pgid: tcgetpgrp(libc::STDIN_FILENO).unwrap(), // libc::STDIN_FILENOは標準入力（0番）
        }
    }

    /// workerスレッドを起動。
    fn spawn(mut self, worker_rx: Receiver<WorkerMsg>, shell_tx: SyncSender<ShellMsg>) {
        thread::spawn(move || {
            for msg in worker_rx.iter() {
                // worker_txからメッセージを受信。
                match msg {
                    WorkerMsg::Cmd(line) => {
                        match parse_cmd(&line) {
                            // コマンド実行メッセージの場合、parse_cmdでメッセージをパース。
                            Ok(cmd) => {
                                if self.built_in_cmd(&cmd, &shell_tx) {
                                    // 組み込みコマンド（シェルの内部コマンド）を実行。
                                    // 組み込みコマンドならworker_rxから受信
                                    continue;
                                }

                                if !self.spawn_child(&line, &cmd) {
                                    // 組み込みコマンドでない場合は、spawn_childを呼び出し、外部プログラムを実行。
                                    // 子プロセス生成に失敗した場合、シェルからの入力を再開
                                    shell_tx.send(ShellMsg::Continue(self.exit_val)).unwrap();
                                }
                            }

                            Err(e) => {
                                eprintln!("ZeroSh: {}", e);
                                shell_tx.send(ShellMsg::Continue(self.exit_val)).unwrap(); // コマンドのパースに失敗した場合は入力を再開するため、main スレッドに通知。
                            }
                        }
                    }
                    WorkerMsg::Signal(SIGCHLD) => {
                        self.wait_child(&shell_tx); // 子プロセスの状態変化管理。SIGCHLDしぐらぬを受信した場合は、wait_childを呼び出し、子プロセスの状態変化を管理。
                    }
                    _ => (), // 無視
                }
            }
        });
    }

    fn built_in_cmd(&mut self, cmd: &[(&str, Vec<&str>)], shell_tx: &SyncSender<ShellMsg>) -> bool {
        if cmd.len() > 1 {
            return false; // 組み込みコマンドのパイプは非対応なのでエラー, 最初のコマンドのみ実行
        }

        match cmd[0].0 {
            "exit" => self.run_exit(&cmd[0].1, shell_tx),
            // "jobs" => self.run_jobs(shell_tx),
            "fg" => self.run_fg(&cmd[0].1, shell_tx),
            // "cd" => self.run_cd(&cmd[0].1, shell_tx),
            _ => false,
        }
    }

    /// 子プロセスを生成。失敗した場合はシェルからの入力を再開させる必要あり。
    fn spawn_child(&mut self, line: &str, cmd: &[(&str, Vec<&str>)]) -> bool {
        assert_ne!(cmd.len(), 0); // コマンドが空でないか検査

        // ジョブIDを取得
        let job_id = if let Some(id) = self.get_new_job_id() {
            id
        } else {
            eprintln!("ZeroSh: 管理可能なジョブを最大値に到達。");
            return false;
        };

        if cmd.len() > 2 {
            eprintln!("ZeroSh: 3つ以上のコマンドによるパイプはサポートしていません");
            return false;
        }

        let mut input = None; // 2つ目のプロセスの標準入力
        let mut output = None; // 1つ目のプロセスの標準出力
        if cmd.len() == 2 {
            // パイプを作成
            let p = pipe().unwrap();
            input = Some(p.0); // 読み取り専用のファイルディスクリプタ(3番)
            output = Some(p.1); // 書き込み専用のファイルディスクリプタ（4番）
        }

        // パイプを閉じる関数を定義
        let cleanup_pipe = CleanUp {
            f: || {
                if let Some(fd) = input {
                    syscall(|| unistd::close(fd)).unwrap();
                }

                if let Some(fd) = output {
                    syscall(|| unistd::close(fd)).unwrap();
                }
            },
        };

        let pgid;
        // 1つ目のプロセスを生成
        match fork_exec(Pid::from_raw(0), cmd[0].0, &cmd[0].1, None, output) {
            // from_rawの引数に0を入れると自動でpgidを割り当てる
            Ok(child) => pgid = child,
            Err(e) => {
                eprintln!("ZeroSh: プロセス生成エラー: {}", e);
                return false;
            }
        }

        // プロセス、ジョブの情報を追加
        let info = ProcInfo {
            state: ProcState::Run,
            pgid,
        };
        let mut pids = HashMap::new();
        pids.insert(pgid, info.clone()); // 1つ目のプロセスの取得

        // 2つ目のプロセスのを生成
        if cmd.len() == 2 {
            match fork_exec(pgid, cmd[1].0, &cmd[1].1, input, None) {
                Ok(child) => {
                    pids.insert(child, info);
                }
                Err(e) => {
                    eprintln!("ZeroSh: プロセス生成エラー: {}", e);
                    return false;
                }
            }
        }

        std::mem::drop(cleanup_pipe); // パイプをクローズ

        // ジョブ情報を追加して子プロセスをフォアグラウンドプロセスグループにする
        self.fg = Some(pgid);
        self.insert_job(job_id, pgid, pids, line);
        tcsetpgrp(libc::STDIN_FILENO, pgid).unwrap();

        true
    }

    /// exitコマンドを実行
    fn run_exit(&mut self, args: &[&str], shell_tx: &SyncSender<ShellMsg>) -> bool {
        // 実行中のジョブがある場合は終了しない
        if !self.jobs.is_empty() {
            eprintln!("ジョブが実行中なので終了できません。");
            self.exit_val = 1; // 失敗
            shell_tx.send(ShellMsg::Continue(self.exit_val)).unwrap(); // シェルを再開
            return true;
        }

        // 終了コードを取得
        let exit_val = if let Some(s) = args.get(1) {
            if let Ok(n) = (*s).parse::<i32>() {
                n
            } else {
                // 終了コードが整数ではない（i32のparseに失敗)
                eprintln!("{}は不正な引数です。", s);
                self.exit_val = 1;
                shell_tx.send(ShellMsg::Continue(self.exit_val)).unwrap(); // シェルを再開
                return true;
            }
        } else {
            self.exit_val
        };

        shell_tx.send(ShellMsg::Quit(exit_val)).unwrap();
        true
    }

    /// 子プロセスの状態変化を管理。
    fn wait_child(&mut self, shell_tx: &SyncSender<ShellMsg>) {
        // WUNTRACED: 子プロセスのていし
        // WNOHANG: ブロックしない
        // WCONTINUED: 実行再開
        let flag = Some(WaitPidFlag::WUNTRACED | WaitPidFlag::WNOHANG | WaitPidFlag::WCONTINUED);

        loop {
            match syscall(|| waitpid(Pid::from_raw(-1), flag)) {
                // from_rawの引き数に-1を指定することで任意の子プロセスの状態変化を検知
                Ok(WaitStatus::Exited(pid, status)) => {
                    // プロセスが終了
                    self.exit_val = status; // 終了コードを保存
                    self.process_term(pid, shell_tx);
                }
                Ok(WaitStatus::Signaled(pid, sig, core)) => {
                    // プロセスがシグナルにより終了
                    eprintln!(
                        "\nZeroSh: 子プロセスがシグナルにより終了{}: pid = {}, signal = {}",
                        if core { "（コアダンプ）" } else { "" },
                        pid,
                        sig
                    );
                }
                // プロセスが停止
                Ok(WaitStatus::Stopped(pid, _sig)) => self.process_stop(pid, shell_tx),
                // プロセスが実行再開
                Ok(WaitStatus::Continued(pid)) => self.process_continue(pid),
                Ok(WaitStatus::StillAlive) => return, // waitすべき子プロセスはいない。
                Err(nix::Error::ECHILD) => return,    // 子プロセスはいない
                Err(e) => {
                    eprintln!("\nZeroSh: waitが失敗: {}", e);
                    exit(1);
                }
                #[cfg(any(target_os = "linux", target_os = "android"))]
                Ok(WaitStatus::PtraceEvent(pid, _, _) | WaitStatus::PtrasySyscall(pid)) => {
                    self.process_stop(pid, shell_tx)
                }
            }
        }
    }

    /// プロセスの終了処理。
    fn process_term(&mut self, pid: Pid, shell_tx: &SyncSender<ShellMsg>) {
        // プロセスのIDを削除し、必要ならフォアグラウンドプロセスにシェルを設定
        if let Some((job_id, pgid)) = self.remove_pid(pid) {
            self.manage_job(job_id, pgid, shell_tx);
        }
    }

    /// プロセスの停止処理。
    fn process_stop(&mut self, pid: Pid, shell_tx: &SyncSender<ShellMsg>) {
        self.set_pid_state(pid, ProcState::Stop); // プロセスを停止中に設定
        let pgid = self.pid_to_info.get(&pid).unwrap().pgid; // プロセスグループIDを取得
        let job_id = self.pgid_to_pids.get(&pgid).unwrap().0; // ジョブIDを取得
        self.manage_job(job_id, pgid, shell_tx); // 必要ならフォアグラウンドプロセスをシェルに設定
    }

    /// プロセスの再開処理
    fn process_continue(&mut self, pid: Pid) {
        self.set_pid_state(pid, ProcState::Run);
    }

    ///　ジョブの管理。引数には変化のあったジョブとプロセスグループを指定。
    ///
    /// - フォアグラウンドプロセスが空の場合、シェルをフォアグラウンドに設定。
    /// - フォアグラウンドプロセスが全て停止中の場合、シェルをフォアグラウンドに設定。
    fn manage_job(&mut self, job_id: usize, pgid: Pid, shell_tx: &SyncSender<ShellMsg>) {
        let is_fg = self.fg.map_or(false, |x| pgid == x); // フォアグラウンドのプロセスか?
        let line = &self.jobs.get(&job_id).unwrap().1;
        if is_fg {
            // 状態が変化したプロセスはフォアグラウンドに設定
            if self.is_group_empty(pgid).unwrap() {
                // フォアグラウンドプロセスが空の場合、
                // ジョブ情報を削除してシェルをフォアグラウンドに設定
                eprintln!("[{}] 終了\t{}", job_id, line);
                self.remove_job(job_id);
                self.set_shell_fg(shell_tx);
            } else if self.is_group_stop(pgid).unwrap() {
                // フォアグラウンドプロセスが全て停止中の場合、シェルをフォアグラウンドに設定
                eprintln!("\n[{}] 停止\t{}", job_id, line);
                self.set_shell_fg(shell_tx);
            }
        } else {
            // プロセスグループが空の場合、ジョブ情報を削除
            if self.is_group_empty(pgid).unwrap() {
                eprintln!("\n[{}] 終了\t{}", job_id, line);
                self.remove_job(job_id);
            }
        }
    }

    /// fgコマンドを実行。
    fn run_fg(&mut self, args: &[&str], shell_tx: &SyncSender<ShellMsg>) -> bool {
        self.exit_val = 1; // とりあえず失敗に設定

        // 引数をチェック
        if args.len() < 2 {
            eprintln!("usage: fg <num>");
            shell_tx.send(ShellMsg::Continue(self.exit_val)).unwrap(); // シェルを再開
            return false;
        }

        // ジョブIDを取得
        if let Ok(n) = args[1].parse::<usize>() {
            if let Some((pgid, cmd)) = self.jobs.get(&n) {
                eprintln!("[{}] 再開\t{}", n, cmd);

                // フォアグラウンドプロセスに設定
                self.fg = Some(*pgid);
                tcsetpgrp(libc::STDIN_FILENO, *pgid).unwrap();

                // ジョブの実行を再開
                killpg(*pgid, Signal::SIGCONT).unwrap();
                return true;
            }
        };

        // 失敗
        eprintln!("{}というジョブは見つかりませんでした。", args[1]);
        shell_tx.send(ShellMsg::Continue(self.exit_val)).unwrap(); // シェルを再開
        true
    }

    /// 新たなジョブ情報を追加。
    fn insert_job(&mut self, job_id: usize, pgid: Pid, pids: HashMap<Pid, ProcInfo>, line: &str) {
        assert!(!self.jobs.contains_key(&job_id));
        self.jobs.insert(job_id, (pgid, line.to_string())); // ジョブ情報を追加

        let mut procs = HashSet::new(); // pgid_to_pidsへ追加するプロセス
        for (pid, info) in pids {
            procs.insert(pid);

            assert!(!self.pid_to_info.contains_key(&pid));
            self.pid_to_info.insert(pid, info); // プロセスの情報を追加
        }

        assert!(!self.pid_to_info.contains_key(&pgid));
        self.pgid_to_pids.insert(pgid, (job_id, procs)); // プロセスグループの情報を追加
    }

    /// プロセスの実行状態を設定し、以前の状態を返す。
    /// pidが存在しないプロセスの場合はNoneを返す。
    fn set_pid_state(&mut self, pid: Pid, state: ProcState) -> Option<ProcState> {
        let info = self.pid_to_info.get_mut(&pid)?;
        Some(replace(&mut info.state, state)) // info.stateとstateの情報を入れ替える
    }

    /// プロセスの情報を削除し、削除できた場合はプロセスの所属する
    /// (ジョブID、プロセスグループID)を返す。
    /// 存在しないプロセスの場合はNoneを返す。
    fn remove_pid(&mut self, pid: Pid) -> Option<(usize, Pid)> {
        let pgid = self.pid_to_info.get(&pid)?.pgid; // プロセスグループIDを取得
        let it = self.pgid_to_pids.get_mut(&pgid)?;
        it.1.remove(&pid); // プロセスグループからpidを削除
        let job_id = it.0; // ジョブIDを取得
        Some((job_id, pgid))
    }

    /// ジョブ情報を削除し、関連するプロセスグループの情報も削除。
    fn remove_job(&mut self, job_id: usize) {
        if let Some((pgid, _)) = self.jobs.remove(&job_id) {
            if let Some((_, pids)) = self.pgid_to_pids.remove(&pgid) {
                assert!(pids.is_empty()); // ジョブを削除する時はプロセスグループは空のはず
            }
        }
    }

    /// 空のプロセスグループなら真。
    fn is_group_empty(&self, pgid: Pid) -> Option<bool> {
        Some(self.pgid_to_pids.get(&pgid)?.1.is_empty())
    }

    /// プロセスグループのプロセス全てが停止中なら真。
    fn is_group_stop(&self, pgid: Pid) -> Option<bool> {
        for pid in self.pgid_to_pids.get(&pgid)?.1.iter() {
            if self.pid_to_info.get(pid).unwrap().state == ProcState::Run {
                return Some(false);
            }
        }
        Some(true)
    }

    /// シェルをフォアグラウンドに設定
    fn set_shell_fg(&mut self, shell_tx: &SyncSender<ShellMsg>) {
        self.fg = None; // fgの値が必要なければ単なる代入で良い。必要ならtake（）で取得。
        tcsetpgrp(libc::STDIN_FILENO, self.shell_pgid).unwrap();
        shell_tx.send(ShellMsg::Continue(self.exit_val)).unwrap();
    }

    /// 新たなジョブIDを取得。
    fn get_new_job_id(&self) -> Option<usize> {
        for i in 0..=usize::MAX {
            if !self.jobs.contains_key(&i) {
                // jobに使われていない最小値を返す。
                return Some(i);
            }
        }
        None
    }
}

type CmdResult<'a> = Result<Vec<(&'a str, Vec<&'a str>)>, DynError>;

/// コマンドをパース
fn parse_cmd(line: &str) -> CmdResult {
    let mut result = vec![];

    for cmd in line.split('|').map(|s| s.trim()) {
        let mut parts = cmd.split_whitespace();
        if let Some(command) = parts.next() {
            let args: Vec<&str> = parts.collect();
            result.push((command, args));
        }
    }

    Ok(result)
}

/// プロセスグループIDを指定してfork & exec。
/// pgidが0の場合は子プロセスのプロセスIDが、プロセスグループIDとなる。
///
/// - inputがSome(fd)の場合は、標準入力をfdと設定。
/// - outputがSome(fd)の場合は、標準出力をfdと設定。
fn fork_exec(
    pgid: Pid,
    filename: &str,
    args: &[&str],
    input: Option<i32>,
    output: Option<i32>,
) -> Result<Pid, DynError> {
    let filename = CString::new(filename).unwrap();
    let args: Vec<CString> = args.iter().map(|&s| CString::new(s).unwrap()).collect();

    match syscall(|| unsafe { fork() })? {
        ForkResult::Parent { child, .. } => {
            // 子プロセスのプロセスグループIDをpgidに設定
            setpgid(child, pgid).unwrap();
            Ok(child)
        }
        ForkResult::Child => {
            setpgid(Pid::from_raw(0), pgid).unwrap();

            // 標準入出力を設定
            if let Some(infd) = input {
                syscall(|| dup2(infd, libc::STDIN_FILENO)).unwrap();
            }
            if let Some(outfd) = output {
                syscall(|| dup2(outfd, libc::STDOUT_FILENO)).unwrap();
            }

            // signal_hookで利用されるUnixドメインソケットとpipeをクローズ（標準入出力と標準エラー出力以外のファイルディスクプリタ）
            for i in 3..=6 {
                let _ = syscall(|| unistd::close(i));
            }

            // 実行ファイルをメモリに読み込み
            match execvp(&filename, &args) {
                Err(_) => {
                    unistd::write(libc::STDERR_FILENO, "不明なコマンドを実行\n".as_bytes()).ok(); // ok(): Converts from Result<T, E> to Option<T>
                    exit(1);
                }
                Ok(_) => unreachable!(), // このコードに到達しないことを明示。
            }
        }
    }
}

/// ドロップ時にクロージャFを呼び出す型。
struct CleanUp<F>
where
    F: Fn(),
{
    f: F,
}

impl<F> Drop for CleanUp<F>
where
    F: Fn(),
{
    fn drop(&mut self) {
        // クロージャをドロップ時に実行v
        (self.f)()
    }
}
