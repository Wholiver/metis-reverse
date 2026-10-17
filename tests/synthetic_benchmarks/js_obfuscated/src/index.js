const fs = require("fs");

const ActiveCryptoUtil = typeof CryptoUtil !== "undefined" ? CryptoUtil : require("./crypto_util").CryptoUtil;
const ActiveSessionManager = typeof SessionManager !== "undefined" ? SessionManager : require("./session_manager").SessionManager;

function parseCommandLineArgs() {
  const args = process.argv.slice(2);
  const options = {
    action: "help",
    secret: "metis_default_hmac_secret_2026",
    user: "alice",
    role: "user",
    now: 1700000000,
    ttl: 3600,
    token: null,
    sessionId: null,
    fromStdin: false,
    version: false,
    help: false
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--help") options.help = true;
    else if (arg === "--version") options.version = true;
    else if (arg === "--stdin") options.fromStdin = true;
    else if (arg.startsWith("--action=")) options.action = arg.split("=")[1];
    else if (arg.startsWith("--secret=")) options.secret = arg.split("=")[1];
    else if (arg.startsWith("--user=")) options.user = arg.split("=")[1];
    else if (arg.startsWith("--role=")) options.role = arg.split("=")[1];
    else if (arg.startsWith("--now=")) options.now = parseInt(arg.split("=")[1], 10);
    else if (arg.startsWith("--ttl=")) options.ttl = parseInt(arg.split("=")[1], 10);
    else if (arg.startsWith("--session-id=")) options.sessionId = arg.split("=")[1];
    else if (arg.startsWith("--token=")) options.token = arg.split("=")[1];
  }

  return options;
}

function runCLI() {
  const options = parseCommandLineArgs();

  if (options.help) {
    console.log("Usage: node bundle.min.js [options]");
    console.log("Options:");
    console.log("  --action=create|validate|hash");
    console.log("  --secret=KEY");
    console.log("  --user=USERNAME");
    console.log("  --role=ROLE");
    console.log("  --now=TIMESTAMP");
    console.log("  --stdin");
    console.log("  --version");
    console.log("  --help");
    process.exit(0);
  }

  if (options.version) {
    console.log("js_obfuscated v1.0.0 (node/es6)");
    process.exit(0);
  }

  const crypto = new ActiveCryptoUtil(options.secret);
  const manager = new ActiveSessionManager(crypto, options.ttl);

  if (options.fromStdin) {
    let input = "";
    try {
      input = fs.readFileSync(0, "utf-8").trim();
    } catch (e) {
      input = "";
    }
    if (!input) {
      console.error("[ERROR] Empty payload from stdin");
      process.exit(1);
    }
    try {
      const parsed = JSON.parse(input);
      if (parsed.op === "hash") {
        const hash = crypto.computeHash(parsed.data);
        console.log(JSON.stringify({ op: "hash", result: hash }));
      } else if (parsed.op === "sign") {
        const sig = crypto.signToken(parsed.payload);
        console.log(JSON.stringify({ op: "sign", signature: sig }));
      } else {
        console.error(`[ERROR] Unknown stdin operation: ${parsed.op}`);
        process.exit(3);
      }
    } catch (err) {
      console.error(`[ERROR] JSON parsing error: ${err.message}`);
      process.exit(2);
    }
    return;
  }

  switch (options.action) {
    case "create": {
      const sess = manager.createSession(options.user, options.role, options.now);
      console.log(JSON.stringify(sess));
      break;
    }
    case "hash": {
      const hash = crypto.computeHash(options.user);
      console.log(JSON.stringify({ input: options.user, hash }));
      break;
    }
    case "validate": {
      if (!options.sessionId || !options.token) {
        console.error("[ERROR] Missing --session-id or --token parameter");
        process.exit(1);
      }
      try {
        const sess = manager.createSession(options.user, options.role, options.now - 100);
        sess.sessionId = options.sessionId;
        manager._sessions.set(options.sessionId, sess);

        const res = manager.validateSessionToken(options.sessionId, options.token, options.now);
        console.log(JSON.stringify(res));
      } catch (err) {
        console.error(`[ERROR] ${err.message}`);
        process.exit(1);
      }
      break;
    }
    default: {
      console.error(`[ERROR] Unknown action: ${options.action}`);
      process.exit(1);
    }
  }
}

runCLI();
