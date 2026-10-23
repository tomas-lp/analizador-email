import chef from "cyberchef";

const MAX_INPUT_CHARS = 16_000;

async function readInput() {
    let raw = "";
    process.stdin.setEncoding("utf8");
    for await (const chunk of process.stdin) raw += chunk;
    return JSON.parse(raw);
}

try {
    const payload = await readInput();
    if (typeof payload.input !== "string" || !payload.input.trim()) {
        throw new Error("Se requiere texto no vacío en 'input'.");
    }
    if (payload.input.length > MAX_INPUT_CHARS) {
        throw new Error(`La entrada supera el límite local de ${MAX_INPUT_CHARS} caracteres.`);
    }

    const depth = Number.isInteger(payload.depth) && payload.depth > 0
        ? Math.min(payload.depth, 5)
        : 3;
    const result = await chef.bake(payload.input, [{
        op: "Magic",
        args: [depth, false, false],
    }]);

    process.stdout.write(JSON.stringify({
        output: String(result.value),
        type: result.type,
        depth,
    }));
} catch (error) {
    process.stderr.write(`${error.message || String(error)}\n`);
    process.exitCode = 1;
}
