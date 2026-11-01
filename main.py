import argparse
import json
import logging
import requests
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="GraphQL Introspection Scanner")
    parser.add_argument("url", help="The GraphQL endpoint URL.")
    parser.add_argument("-o", "--output", help="Output file for the schema (JSON format).", default=None)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    parser.add_argument("-d", "--depth", type=int, default=3, help="Set the max depth for the schema introspection.")
    return parser

# Depth is clamped here instead of rejected: main stops anything under 1,
# but a depth of 50 quietly becomes 10. The query stays bounded either way,
# and a wrapped type deeper than ten levels just comes back truncated.
def build_typeref_fragment(depth: int) -> str:
    """Builds the TypeRef fragment with exactly depth levels of ofType nesting."""
    depth = max(1, min(int(depth), 10))
    inner = "kind\n      name"
    for _ in range(depth):
        inner = "kind\n      name\n      ofType {\n        " + inner + "\n      }"
    return "fragment TypeRef on __Type {\n      " + inner + "\n    }"


def introspect_graphql_schema(url: str, depth: int = 3) -> dict | None:
    """
    Performs a GraphQL introspection query to retrieve the schema.

    Args:
        url (str): The GraphQL endpoint URL.
        depth (int): the max depth for the schema introspection

    Returns:
        dict | None: The GraphQL schema as a dictionary, or None if an error occurred.
    """
    typeref_fragment = build_typeref_fragment(depth)
    query = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args {
            ...InputValue
          }
        }
      }
    }

    fragment FullType on __Type {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }

    fragment InputValue on __InputValue {
      name
      description
      type { ...TypeRef }
      defaultValue
    }

    """ + "\n    " + typeref_fragment + "\n"
    try:
        response = requests.post(url, json={'query': query}, timeout=10)  # Added timeout
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        data = response.json()
        # Any errors key at all ends this, even when the same response also
        # carries a usable data block. GraphQL allows partial data beside
        # errors; I treat a partial schema as no schema rather than grade
        # half of an API surface.
        if 'errors' in data:
            logging.error(f"GraphQL introspection query failed: {data['errors']}")
            return None
        return data['data']['__schema']
    except requests.exceptions.RequestException as e:
        logging.error(f"Request error: {e}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"JSON decode error: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

def analyze_schema(schema: dict) -> dict:
  """
  Analyzes a GraphQL schema for potential vulnerabilities.
  This is a placeholder; implement actual analysis logic here.

  Args:
      schema (dict): The GraphQL schema as a dictionary.

  Returns:
      dict: A dictionary of potential vulnerabilities identified.
  """
  # Placeholder for vulnerability analysis
  vulnerabilities = {}
  if schema:
        logging.info("Schema retrieved successfully. Starting analysis...")
        types = schema.get('types')
        if not isinstance(types, list):
            logging.warning("Malformed schema: 'types' is missing or is not a list. Analysis skipped.")
            vulnerabilities['malformed_schema'] = "Schema has no usable 'types' list."
            return vulnerabilities
        # Check for sensitive fields (e.g., password, email, etc.)
        sensitive_fields = []
        for type_def in types:
            if type_def and 'fields' in type_def and type_def['fields']:
                for field in type_def['fields']:
                    # Substring match on the field name only. Arguments and
                    # input fields are never scanned, and a type named
                    # SecretStore with plain fields draws no finding.
                    if field and field['name'] and ('password' in field['name'].lower() or 'email' in field['name'].lower() or 'secret' in field['name'].lower()):
                        sensitive_fields.append({
                            'type': type_def['name'],
                            'field': field['name']
                        })
        if sensitive_fields:
          vulnerabilities['sensitive_fields'] = sensitive_fields
          logging.warning(f"Found potentially sensitive fields: {sensitive_fields}")
        else:
          logging.info("No potentially sensitive fields found.")


  else:
      logging.warning("No schema provided for analysis.")
  return vulnerabilities


def main():
    """
    Main function to drive the GraphQL introspection scanner.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    logging.info(f"Starting GraphQL introspection scan for URL: {args.url}")

    # Input Validation: Ensure URL is a valid URL (basic check)
    if not args.url.startswith("http://") and not args.url.startswith("https://"):
        logging.error("Invalid URL. Please provide a URL starting with http:// or https://")
        sys.exit(1)

    if args.depth < 1:
        logging.error("Invalid depth. Depth must be at least 1.")
        sys.exit(1)

    schema = introspect_graphql_schema(args.url, args.depth)

    if schema and not isinstance(schema.get('types'), list):
        logging.error("Malformed schema: the endpoint returned a schema with no 'types' list. No analysis was performed.")
        sys.exit(1)

    if schema:
        # Analyze the schema for vulnerabilities
        vulnerabilities = analyze_schema(schema)

        if args.output:
            try:
                with open(args.output, 'w') as outfile:
                    json.dump(schema, outfile, indent=4)
                logging.info(f"Schema saved to: {args.output}")

                # The findings file only exists in output mode, named by
                # appending to the schema path. In console mode the same
                # findings are printed under the schema instead.
                if vulnerabilities:
                  with open(args.output + ".vulns.json", 'w') as outfile:
                    json.dump(vulnerabilities, outfile, indent=4)
                    logging.info(f"Potential Vulnerabilities saved to: {args.output + '.vulns.json'}")

            except IOError as e:
                logging.error(f"Error writing to file: {e}")
        else:
          print(json.dumps(schema, indent=4))
          if vulnerabilities:
            print("Potential Vulnerabilities:\n")
            print(json.dumps(vulnerabilities, indent=4))

    else:
        logging.error("Failed to retrieve GraphQL schema.")
        sys.exit(1)

    logging.info("GraphQL introspection scan completed.")

if __name__ == "__main__":
    # Example Usage
    # python main.py https://example.com/graphql -o schema.json -v
    # python main.py https://example.com/graphql
    main()