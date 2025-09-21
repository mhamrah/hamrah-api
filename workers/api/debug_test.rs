use hamrah_api::utils::url_canonicalize;

fn main() {
    let (canon, _) = url_canonicalize("https://example.com//foo///bar/").unwrap();
    println!("Canonicalized URL: {}", canon);
    println!("Contains '/foo/bar': {}", canon.contains("/foo/bar"));
    println!("Contains '//foo': {}", canon.contains("//foo"));
}
