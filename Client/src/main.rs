extern crate clap;
extern crate crypto;

use clap::{Command,Arg};
use crypto::aessafe::{AesSafe256Encryptor, AesSafe256Decryptor};
use std::process;


fn main() {

    let apiRoot = "GPAD_ROOT";

    let app = Command::new("gpad-cli")
        .version("0.0.1")
        .author("noko1024")
        .about("GitPATLink CLI Client")
        .subcommand(Command::new("add")
            .about("PAT additions or updates")
            .arg(Arg::new("student ID Number")
                .help("pXXXXXX or sXXXXXX")
                .required(true)
            )
            .arg(Arg::new("password")
                .help("Your password")
                .required(true)
            )
            .arg(Arg::new("Pasonal Access Token")
                .help("Your Pasonal Access Token")
                .required(true)
            )
        )
        .subcommand(Command::new("get")
            .about("PAT additions and updates")
            .arg(Arg::new("student ID number")
            .help("pXXXXXX or sXXXXXX")
                .required(true)
            )
            .arg(Arg::new("password")
                .help("Your password")
                .required(true)
            )
        )
        .subcommand(Command::new("remove")
        .about("PAT additions and updates")
        .arg(Arg::new("student ID number")
        .help("pXXXXXX or sXXXXXX")
            .required(true)
        )
        .arg(Arg::new("password")
            .help("Your password")
            .required(true)
        )
    );
    // 引数を解析
    let matches = app.get_matches();

    // subサブコマンドの解析結果を取得
    if let Some(ref matches) = matches.subcommand_matches("add") {
        let id = matches.value_of("student ID Number").unwrap().to_string();
        let password = matches.value_of("password").unwrap().to_string();
        let token = matches.value_of("Pasonal Access Token").unwrap().to_string();
        println!("{}",id);
        println!("{}",password);
        println!("{}",token);
        let encToken = _encrypt(token, password);

    }
    else if let Some(ref matches) = matches.subcommand_matches("get") {
        let id = matches.value_of("student ID number").unwrap().to_string();
        let password = matches.value_of("password").unwrap().to_string();
        println!("{}",id);
        println!("{}",password);
    }
    else if let Some(ref matches) = matches.subcommand_matches("remove") {
        let id = matches.value_of("student ID number").unwrap().to_string();
        let password = matches.value_of("password").unwrap().to_string();
        println!("{}",id);
        println!("{}",password);
    }

    fn _encrypt(source:String, password:String) -> String {
        return String::from("pass");
    }
    
    fn _decrypt(){

    }

}
