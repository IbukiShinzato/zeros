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
