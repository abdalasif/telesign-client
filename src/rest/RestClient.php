<?php

namespace telesign\sdk\rest;

use GuzzleHttp\Client;
use GuzzleHttp\RequestOptions;
use Ramsey\Uuid\Uuid;

use const telesign\sdk\version\VERSION;

/**
 * The TeleSign RestClient is a generic HTTP REST client that can be extended to make requests against any of
 * TeleSign's REST API endpoints.
 *
 * RequestEncodingMixin offers the function _encode_params for url encoding the body for use in string_to_sign outside
 * of a regular HTTP request.
 *
 * See https://developer.telesign.com for detailed API documentation.
 */
class RestClient {

  protected $customer_id;
  protected $api_key;
  protected $user_agent;
  protected $client;

  /**
   * TeleSign RestClient instantiation function
   *
   * @param string   $customer_id   Your customer_id string associated with your account
   * @param string   $api_key       Your api_key string associated with your account
   * @param string   $rest_endpoint Override the default rest_endpoint to target another endpoint string
   * @param float    $timeout       How long to wait for the server to send data before giving up
   * @param string   $proxy         URL of the proxy
   * @param callable $handler       Guzzle's HTTP transfer override
   */
  function __construct (
    $customer_id,
    $api_key,
    $rest_endpoint = "https://rest-api.telesign.com",
    $timeout = 10,
    $proxy = null,
    $handler = null
  ) {
    $this->customer_id = $customer_id;
    $this->api_key = $api_key;

    $this->client = new Client([
      "base_uri" => $rest_endpoint,
      "timeout" => $timeout,
      "proxy" => $proxy,
      "handler" => $handler
    ]);

    $sdk_version = VERSION;
    $php_version = PHP_VERSION;
    $guzzle_version = Client::MAJOR_VERSION;

    $this->user_agent = "TeleSignSDK/php-$sdk_version PHP/$php_version Guzzle/$guzzle_version";
  }

  /**
   * Generates the TeleSign REST API headers used to authenticate requests.
   *
   * Creates the canonicalized string_to_sign and generates the HMAC signature. This is used to authenticate requests
   * against the TeleSign REST API.
   *
   * See https://developer.telesign.com/docs/authentication-1 for detailed API documentation.
   *
   * @param string $customer_id        Your account customer_id
   * @param string $api_key            Your account api_key
   * @param string $method_name        The HTTP method name of the request, should be one of 'POST', 'GET', 'PUT' or
   *                                   'DELETE'
   * @param string $resource           The partial resource URI to perform the request against
   * @param array $fields  HTTP body parameters array to perform the HTTP request with
   * @param string $date               The date and time of the request
   * @param string $nonce              A unique cryptographic nonce for the request
   * @param string $user_agent         User Agent associated with the request
   *
   * @return array The TeleSign authentication headers
   * @throws \Exception
   */
  public static function generateTelesignHeaders(
    string $customerId,
    string $apiKey,
    string $httpMethod,
    string $contentType,
    string $path,
    string|null $body = null,
    string|null $nonce = null,
    string|null $date = null,
    string|null $userAgent = null
  ): array {
    // Prepare date and nonce
    $date = $date ?? gmdate('D, d M Y H:i:s \G\M\T');
    $nonce = $nonce ?? Uuid::uuid4()->toString();
    $authMethod = 'HMAC-SHA256';

    $headers = [
      'Content-Type' => $contentType,
//      'X-TS-Auth-Method' => $authMethod,
//      'X-TS-Nonce' => $nonce,
//      'X-TS-Date' => $date,
    ];

    // Prepare the string-to-sign
    $stringToSign = strtoupper($httpMethod) . "\n" .
      strtolower($contentType) . "\n" .
      "\n" . //for Date header
      "x-ts-auth-method: $authMethod\n" .
      "x-ts-date: $date\n" .
      "x-ts-nonce: $nonce\n" .
      ($body !== null ? $body : null) .
      "\n" . $path;

    // Base64 decode the API key
    $decodedApiKey = base64_decode($apiKey);

    // Create HMAC hash using the decoded API key and the string-to-sign
    $hash = hash_hmac('sha256', $stringToSign, $decodedApiKey, true);

    // Base64 encode the resulting hash to create the signature
    $signature = base64_encode($hash);

    // Create the Authorization header
//    $headers['Authorization'] = 'TSA ' . $customerId . ':' . $signature;
    $headers['Authorization'] = 'Basic ' . base64_encode($customerId . ':' . $apiKey);

    if (null !== $userAgent) {
      $headers["User-Agent"] = $userAgent;
    }

    // Sort headers alphabetically
    ksort($headers);

    return $headers;
  }

  /**
   * Generic TeleSign REST API POST handler
   *
   * @param string $resource The partial resource URI to perform the request against
   * @param array  $fields   Body params to perform the POST request with
   * @param string $date     The date and time of the request
   * @param string $nonce    A unique cryptographic nonce for the request
   *
   * @return \telesign\sdk\rest\Response The RestClient Response object
   */
  function post (...$args) {
    return $this->execute("POST", ...$args);
  }

  /**
   * Generic TeleSign REST API GET handler
   *
   * @param string $resource The partial resource URI to perform the request against
   * @param array  $fields   Query params to perform the GET request with
   * @param string $date     The date and time of the request
   * @param string $nonce    A unique cryptographic nonce for the request
   *
   * @return \telesign\sdk\rest\Response The RestClient Response object
   */
  function get (...$args) {
    return $this->execute("GET", ...$args);
  }

  /**
   * Generic TeleSign REST API PUT handler
   *
   * @param string $resource The partial resource URI to perform the request against
   * @param array  $fields   Query params to perform the DELETE request with
   * @param string $date     The date and time of the request
   * @param string $nonce    A unique cryptographic nonce for the request
   *
   * @return \telesign\sdk\rest\Response The RestClient Response object
   */
  function put (...$args) {
    return $this->execute("PUT", ...$args);
  }

  /**
   * Generic TeleSign REST API PATCH handler
   *
   * @param string $resource The partial resource URI to perform the request against
   * @param array  $fields   Query params to perform the DELETE request with
   * @param string $date     The date and time of the request
   * @param string $nonce    A unique cryptographic nonce for the request
   *
   * @return \telesign\sdk\rest\Response The RestClient Response object
   */
  function patch (...$args) {
    return $this->execute("PATCH", ...$args);
  }

  /**
   * Generic TeleSign REST API DELETE handler
   *
   * @param string $resource The partial resource URI to perform the request against
   * @param array  $fields   Query params to perform the DELETE request with
   * @param string $date     The date and time of the request
   * @param string $nonce    A unique cryptographic nonce for the request
   *
   * @return \telesign\sdk\rest\Response The RestClient Response object
   */
  function delete (...$args) {
    return $this->execute("DELETE", ...$args);
  }

  /**
   * Generic TeleSign REST API request handler
   *
   * @param string $resource The partial resource URI to perform the request against
   * @param array  $fields   Body of query params to perform the HTTP request with
   * @param string $date     The date and time of the request
   * @param string $nonce    A unique cryptographic nonce for the request
   *
   * @return \telesign\sdk\rest\Response The RestClient Response object
   */
   protected function execute ($method_name, $resource, $fields = [], $contentType = null, $date = null, $nonce = null) {
     if(null === $contentType) {
       $contentType = 'application/x-www-form-urlencoded';
     }

     $body = null;

     if(count($fields) !== 0 && $contentType === 'application/json') {
       $body = json_encode($fields);
     }

     if(count($fields) !== 0 && $contentType === 'application/x-www-form-urlencoded') {
       $body = http_build_query($fields, "", "&");
     }

    $headers = $this->generateTelesignHeaders(
      $this->customer_id,
      $this->api_key,
      $method_name,
      $contentType,
      $resource,
      $body,
      $nonce,
      $date,
      $this->user_agent
    );

    $options = [
      RequestOptions::HEADERS => $headers,
      RequestOptions::HTTP_ERRORS => false
    ];

    /* Add json body if request is PUT, PATCH OR POST */
    if(
      count($fields) !== 0
      && in_array($method_name, [ "POST", "PUT", "PATCH" ])
    ) {
      $options[RequestOptions::BODY] = $body;
    }

     /* Add query in URL if request is GET or DELETE */
     if(
       count($fields) !== 0
       && in_array($method_name, [ "GET", "DELETE" ])
     ) {
       $options[RequestOptions::QUERY] = $body;
     }

    return new Response($this->client->request($method_name, $resource, $options));
  }
}
