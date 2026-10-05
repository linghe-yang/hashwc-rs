//! Offline search oracle: one whitespace-separated "threshold weight..." per line.
//! Calls the production circuit builder; never runs network protocols.
use std::io::{self, BufRead, Write};
use wcss::{Circuit, Limits};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line?;
        let fields: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
        if fields.len() < 3 {
            return Err("expected threshold and at least two weights".into());
        }
        let policy = types::Policy::from_strings(&fields[1..], &fields[0])?;
        policy.validate_async()?;
        let circuit = Circuit::build(policy, Limits::default())?;
        let ands = circuit
            .gates()
            .iter()
            .filter(|g| matches!(g.op, wcss::Op::And))
            .count();
        writeln!(
            stdout,
            "{{\"parties\":{},\"gates\":{},\"and_gates\":{},\"or_gates\":{}}}",
            circuit.policy().n(),
            circuit.gates().len(),
            ands,
            circuit.gates().len() - ands
        )?;
        stdout.flush()?;
    }
    Ok(())
}
