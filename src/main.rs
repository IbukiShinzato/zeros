mod helper;
mod shell;

fn main() {
    use nix::libc;
    println!("{}", libc::STDIN_FILENO);
}
