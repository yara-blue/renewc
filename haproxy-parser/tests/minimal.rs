use haproxy_parser;

#[test]
fn main() {
    let file = include_str!("minimal_haproxy.cfg");
    haproxy_parser::parse(file).unwrap();
}

