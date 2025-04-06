use warp::Filter;
use rand::seq::SliceRandom;

#[tokio::main]
async fn main() {
    // Define listas de adjetivos y nombres
    let adjectives = vec![
        "clever", "brave", "mystic", "stoic", "eager", "happy", "bold", "calm", "daring", "frosty",
        "furious", "gentle", "jolly", "keen", "lively", "proud", "quirky", "sharp", "silent", "vibrant",
    ];

    let names = vec![
        "einstein", "curie", "newton", "tesla", "lovelace", "darwin", "galileo", "copernicus", "fermat", "archimedes",
        "turing", "bohr", "kepler", "hawking", "pasteur", "heisenberg", "maxwell", "nash", "noether", "poincare",
    ];

    // Define la ruta que retorna un nombre al estilo Docker
    let random_name = warp::path::end().map(move || {
        // Genera un nombre aleatorio combinando un adjetivo y un nombre
        let mut rng = rand::thread_rng();
        let adjective = adjectives.choose(&mut rng).unwrap_or(&"mysterious");
        let name = names.choose(&mut rng).unwrap_or(&"unknown");

        // Retorna el nombre combinado
        format!("{}-{}", adjective, name)
    });

    // Inicia el servidor en el puerto 3030
    warp::serve(random_name).run(([0, 0, 0, 0], 3030)).await;
}
