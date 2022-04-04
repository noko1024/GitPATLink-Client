extern crate clap;
extern crate crypto;
extern crate aesstream;
extern crate bcrypt;
extern crate reqwest;
extern crate tokio;
extern crate base64;
extern crate clap_complete;

use aesstream::{AesWriter, AesReader};
use crypto::aessafe::{AesSafe256Encryptor, AesSafe256Decryptor};
use bcrypt::hash;
use std::io::{Read,Write,Cursor};
use std::process;
use std::io;
use std::env;
use clap_complete::{generate, shells::Bash,shells::Elvish,shells::Fish,shells::PowerShell,shells::Zsh};

mod cli;

#[tokio::main]
async fn main(){
    // 引数を解析
    let matches = cli::build_cli().get_matches();

    // subサブコマンドの解析結果を取得
    if let Some(ref matches) = matches.subcommand_matches("comp"){
        let shell_name = matches.value_of("Shell Name").unwrap().to_string();

        if shell_name == "bash" {
            generate(Bash, &mut cli::build_cli(), "gpad-cli", &mut io::stdout());
        }
        else if shell_name == "zsh" {
            generate(Zsh, &mut cli::build_cli(), "gpad-cli", &mut io::stdout());
        }
        else if shell_name == "powershell" {
            generate(PowerShell, &mut cli::build_cli(), "gpad-cli", &mut io::stdout());
        }
        else if shell_name == "fish" {
            generate(Fish, &mut cli::build_cli(), "gpad-cli", &mut io::stdout());
        }
        else if shell_name == "elvish" {
            generate(Elvish, &mut cli::build_cli(), "gpad-cli", &mut io::stdout());
        }

    }
    else if let Some(ref matches) = matches.subcommand_matches("add") {
        let id = matches.value_of("student ID Number").unwrap().to_string();
        let password = matches.value_of("password").unwrap().to_string();
        let token = matches.value_of("Pasonal Access Token").unwrap().to_string();
        //Pasonal Access Tokenを passwordで暗号化
        let enc_token = _encrypt(&password,token);
        //sha256でpasswordをハッシュ化
        let hash_password = hash(password,10).unwrap();

        let res = _http_post("/link/api/add",vec![id.clone(),hash_password,enc_token]).await;
        println!("{}",res)
        

    }
    else if let Some(ref matches) = matches.subcommand_matches("load") {
        let id = matches.value_of("student ID number").unwrap().to_string();
        let password = matches.value_of("password").unwrap().to_string();
        let user_name = matches.value_of("user name").unwrap().to_string();
        let hash_password = hash(&password, 10).unwrap();
        println!("{}",hash_password);
        let raw_token = _http_post("/link/api/get",vec![id.clone(),hash_password]).await;
        let token = _decrypt(&password, raw_token);

        env::set_var("GIT_TOKEN",token);
        env::set_var("GIT_USER",user_name)
    }
    else if let Some(ref matches) = matches.subcommand_matches("remove") {
        let id = matches.value_of("student ID number").unwrap().to_string();
        let password = matches.value_of("password").unwrap().to_string();
        println!("{}",id);
        println!("{}",password);
    }
    else if let Some(ref __) = matches.subcommand_matches("get"){
        let mut input_user_auth = vec![];
        loop {
            let mut word = String::new();
            std::io::stdin().read_line(&mut word).ok();
            let input_string = word.trim().to_string();
            if input_string == "" {
                break;
            }
            else {
                input_user_auth.push(input_string);
            }
        }
        if input_user_auth.len() != 2{
            println!("{:?}",input_user_auth);
            process::exit(1);
        }
        else{
            if input_user_auth[0] != "protocol=https" && input_user_auth[1] != "host=github.com"{
                process::exit(0);
            }
        }
    
        let token = std::env::var("GIT_TOKEN");
        let user_name = std::env::var("GIT_USER");
        //変な入力でも通過できる多分
        if token.is_ok() && user_name.is_ok(){
            println!("protocol=https");
            println!("host=github.com");
            println!("username={}",user_name.unwrap());
            println!("passsword={}",token.unwrap());
        }
        else{
            process::exit(0);
        }
    }
    else if let Some(ref __) = matches.subcommand_matches("store"){
        std::process::exit(0)
    }
    else if let Some(ref __) = matches.subcommand_matches("erase"){
        std::process::exit(0)
    }



    fn _encrypt(password:&str, source:String) -> String  {
        const PASSWORD_SIZE: usize = 32;
        let key = password.as_bytes(); 
        if key.len()>PASSWORD_SIZE{
            println!("Error:Too long password!");
            process::exit(1);
        }
        let mut key_array = [0u8; PASSWORD_SIZE];               
        for i in 0..key.len() {
            key_array[i] = key[i];
        }
        let encryptor = AesSafe256Encryptor::new(&key_array);
        let mut encrypted = vec![];
        {
            let writer = AesWriter::new(&mut encrypted, encryptor);
            let _ = writer.unwrap().write_all(source.as_bytes());
        }
        return base64::encode(encrypted);
    }
    

    fn _decrypt(password:&str, source:String)-> String{
        let decoded:Vec<u8> = base64::decode(source).unwrap();
        const PASSWORD_SIZE: usize = 32;
        let key = password.as_bytes(); 
        if key.len()>PASSWORD_SIZE{
            println!("Error:Too long password!");
            process::exit(1);
        }
        let mut key_array = [0u8; PASSWORD_SIZE];               
        for i in 0..key.len() {
            key_array[i] = key[i];
        }
        let decryptor = AesSafe256Decryptor::new(&key_array);
        let reader = AesReader::new(Cursor::new(decoded), decryptor);
        let mut decrypted = Vec::new();
        let _ = reader.unwrap().read_to_end(&mut decrypted);
        return String::from_utf8(decrypted).unwrap();
    }


    async fn _http_post(api_end_point:&str, user_auth_info:Vec<String>) -> String{
        let api_root = "http://localhost:4000".to_string();
        let request_body:String;

        if user_auth_info.len() <= 2{
            request_body = format!("{{\"id\":\"{}\",\"password\":\"{}\"}}", user_auth_info[0],user_auth_info[1]); 
        }
        else{
            request_body = format!("{{\"id\":\"{}\",\"password\":\"{}\",\"token\":\"{}\"}}", user_auth_info[0],user_auth_info[1],user_auth_info[2]);
        }
        let client = reqwest::Client::new();
        print!("{}",request_body);
        let response = client.post(api_root+api_end_point)
            .header("Content-Type","application/json")
            .body(request_body)
            .send()
            .await;
            
        let response_data;
        match response {
            Ok(o) => {response_data = o;}
            Err(_r) => {
                println!("NetworkError");
                process::exit(1);
            }
        };

        let status_code = response_data.status().as_u16();
        if status_code == 200{
            let res = response_data.text().await;
            let res_text = res.unwrap();
            println!("{}",status_code);
            println!("{}",res_text);
            return res_text;
        }
        else if status_code == 400{
            println!("Error:Internal Client Error");
            println!("Please contact the developer.");
            let res = response_data.text().await;
            let res_text = res.unwrap();
            println!("{}",status_code);
            println!("{}",res_text);
            process::exit(1)
        }
        else if status_code == 401{
            println!("Error:Auth Error");
            println!("Hint:1. Is your password wrong?");
            println!("Hint:2. Possibility that the authentication information has not been registered.");
            let res = response_data.text().await;
            let res_text = res.unwrap();
            println!("{}",status_code);
            println!("{}",res_text);
            process::exit(1)
        }
        else if status_code == 404{
            println!("Error:Client Adress Error");
            println!("Please contact the developer.");
            let res = response_data.text().await;
            let res_text = res.unwrap();
            println!("{}",status_code);
            println!("{}",res_text);
            process::exit(1)
        }
        else{
            println!("Error:Internal Server Error. Please try again");
            let res = response_data.text().await;
            let res_text = res.unwrap();
            println!("{}",status_code);
            println!("{}",res_text);
            process::exit(1)
        }
    }
}
