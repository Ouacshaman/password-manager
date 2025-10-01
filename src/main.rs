use std;

fn main() {
    println!("Hello, world!");
    let args: Vec<String> = std::env::args().collect();
    let stringed_args = args.join(" ");
    println!("You entered: {:?}", stringed_args)
}
