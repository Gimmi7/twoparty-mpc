
use curv::arithmetic::{BasicOps, Modulo};
use curv::BigInt;

fn main() {
    let n = 20; // phi(n)=8
    let e = n;

    let mut vector: Vec<(BigInt, String)> = vec![];
    for z in 1..=n - 1
    {
        // z^e (mod n)
        let f_z = BigInt::from(z).pow(e).modulus(&BigInt::from(n));
        let output = format!("{}^{}={} (mod {})", z, e, f_z, n);
        vector.push((f_z, output))
    }

    vector.sort_by(|a, b| a.0.cmp(&b.0));

    vector.into_iter().for_each(|v| println!("{}", v.1));


    let base = 7;
    let exponent = 199;
    let modulo = 221;
    let result = BigInt::from(base).pow(exponent).modulus(&BigInt::from(modulo));
    println!("{}^{} % {} ={}", base, exponent, modulo, result);
}