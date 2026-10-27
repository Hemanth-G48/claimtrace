export default function format(fmt, value) { return String(fmt).replace(/%s/g, String(value)); }
