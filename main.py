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

def introspect_graphql_schema(url: str, depth: int = 3) -> dict | None:
    """
    Performs a GraphQL introspection query to retrieve the schema.

    Args:
        url (str): The GraphQL endpoint URL.
        depth (int): the max depth for the schema introspection

    Returns:
        dict | None: The GraphQL schema as a dictionary, or None if an error occurred.
    """
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

    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                }
              }
            }
          }
        }
      }
    }
    """
    try:
        response = requests.post(url, json={'query': query}, timeout=10)  # Added timeout
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        data = response.json()
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
        # Check for sensitive fields (e.g., password, email, etc.)
        sensitive_fields = []
        for type_def in schema['types']:
            if type_def and 'fields' in type_def and type_def['fields']:
                for field in type_def['fields']:
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

    schema = introspect_graphql_schema(args.url, args.depth)

    if schema:
        # Analyze the schema for vulnerabilities
        vulnerabilities = analyze_schema(schema)

        if args.output:
            try:
                with open(args.output, 'w') as outfile:
                    json.dump(schema, outfile, indent=4)
                logging.info(f"Schema saved to: {args.output}")

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