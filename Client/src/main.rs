extern crate clap;
extern crate crypto;
extern crate aesstream;
extern crate reqwest;
extern crate tokio;
extern crate rand;
extern crate base64;

use clap::{Command,Arg};
use aesstream::{AesWriter, AesReader};
use crypto::aessafe::{AesSafe256Encryptor, AesSafe256Decryptor};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::io::{Read,Write,Cursor};
use std::process;

#[tokio::main]
async fn main(){

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
        let enc_token = _encrypt(&password,token);
        println!("{}",enc_token);
        println!("enc");
        //let dec_token = _decrypt(&password, enc_token);
        let mut hasher = Sha256::new();
        hasher.input_str(&password.to_string());
        let hex_password = hasher.result_str();
        //println!("{}",dec_token);
        //println!("dec");
        let res = _http_post("/link/api/add",vec![id.clone(),hex_password,enc_token]).await;
        println!("{}",res)
        

    }
    else if let Some(ref matches) = matches.subcommand_matches("get") {
        let id = matches.value_of("student ID number").unwrap().to_string();
        let password = matches.value_of("password").unwrap().to_string();
        let mut hasher = Sha256::new();
        hasher.input_str(&password.to_string());
        let hex_password = hasher.result_str();
        println!("{}",id);
        println!("{}",password);
        let raw_token = _http_post("/link/api/get",vec![id.clone(),hex_password]).await;
        let token = _decrypt(&password, raw_token);
        println!("{}",token);
    }
    else if let Some(ref matches) = matches.subcommand_matches("remove") {
        let id = matches.value_of("student ID number").unwrap().to_string();
        let password = matches.value_of("password").unwrap().to_string();
        println!("{}",id);
        println!("{}",password);
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
            writer.unwrap().write_all(source.as_bytes());
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
        let mut reader = AesReader::new(Cursor::new(decoded), decryptor);
        let mut decrypted = Vec::new();
        reader.unwrap().read_to_end(&mut decrypted);
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
        else if status_code == 403{
            println!("Error:Auth Error");
            println!("Hint:Is your password wrong?");
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
