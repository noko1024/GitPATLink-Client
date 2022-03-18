use clap::{Command,Arg,AppSettings};


pub fn  build_cli() -> Command<'static>{
    let app = Command::new("gpad-cli")
    .version("0.0.1")
    .author("noko1024")
    .about("GitPATLink CLI Client")
    .setting(AppSettings::DeriveDisplayOrder)
    .subcommand(Command::new("comp")
        .about("Generate shell completion file")
        .arg(Arg::new("Shell Name")
            .possible_values(&["bash", "zsh", "powershell", "fish", "elvish"])
            .required(true)
        )
    )
    
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
    return app;
}