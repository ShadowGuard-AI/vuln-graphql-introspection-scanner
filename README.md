# vuln-GraphQL-Introspection-Scanner
Attempts to retrieve the GraphQL schema from a target endpoint to identify potential vulnerabilities related to exposed data structures and queries. - Focused on Assess vulnerabilities in web applications by performing scans and providing detailed reports

## Install
`git clone https://github.com/ShadowGuard-AI/vuln-graphql-introspection-scanner`
`pip install -r requirements.txt`

## Usage
`python main.py <url> [params]`

Example: `python main.py http://127.0.0.1:4000/graphql -o schema.json`

Without `-o`, the schema and any findings are printed to the console. With `-o`, the schema is written to that file and any findings are written to `<output>.vulns.json`. The scan exits non-zero when no schema is retrieved or the returned schema has no usable `types` list.

## Parameters
- `url` (positional, required): The GraphQL endpoint URL. It must start with http:// or https://.
- `-h`: Show help message and exit
- `-o` / `--output`: Output file for the schema (JSON format).
- `-v`: Enable verbose logging.
- `-d`: Set the max depth for the schema introspection. The depth controls how many levels of nested `ofType` the TypeRef fragment in the introspection query expands (1 to 10). Values above 10 are clamped to 10; values below 1 are rejected.

## License
MIT License (see LICENSE).
