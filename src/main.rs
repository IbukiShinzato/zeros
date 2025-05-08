// mod helper;
mod shell;

/// コマンドをパース
fn parse_cmd(line: &str) -> () {
    let commands: Vec<&str> = line.split('|').map(|x| x.trim()).collect();
    let mut result = vec![];

    for cmd in commands {
        match cmd {
            "" => panic!("Invalid arguments"),
            _ => {
                let command: Vec<&str> = cmd.split(" ").collect();
                if let Some(&c) = command.get(0) {
                    if let Some(_) = command.get(1) {
                        let mut args = vec![];
                        for i in 1..command.len() {
                            let arg = command[i];
                            args.push(arg);
                        }
                        result.push((c, args))
                    } else {
                        result.push((c, vec![]));
                    }
                }
            }
        }
    }

    println!("{:?}", result);
}

fn main() {
    // let line = "echo hello | |  less";
    let line = "echo hello | less | cat";
    parse_cmd(line);

    use nix::libc;
    println!("{}", libc::STDIN_FILENO);
}
