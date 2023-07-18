interface Logger {
  log: (msg: string) => void
}

let __logger: Logger = {
  log: (msg: string) => {
    console.log(msg);
  }
};

export function setLogger(logger: Logger) {
  __logger = logger;
}

export function getLogger(): Logger {
  return __logger;
}