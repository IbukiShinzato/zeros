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
    path::PathBuf,
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
        Worker::new().spawn(worker_rx, worker_tx);

        let exit_val; // 終了コード
        let mut prev = 0; // 直前の終了コード
        loop {
            // 1行読み込んで、その行をworkerスレッドに送信
            let face = if prev == 0 { '\u{1F642}' } else { '\u{1F480}' };
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
                                if self.build_in_cmd(&cmd, &shell_tx) {
                                    // 組み込みコマンド（シェルの内部コマンド）を実行。
                                    // 組み込みコマンドならworker_rxから受信
                                    continue;
                                }

                                if !self.spawn_child(&line, &cmd) {
                                    // 組み込みコマンドでない場合は、spawn_childを呼び出し、外部プログラムを実行。
                                    // 子プロセス生成に失敗した場合、シェルからの入力を再開
                                    shell_tx.send(ShellMsg::Continue(self.exit_val).unwrap());
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
}
