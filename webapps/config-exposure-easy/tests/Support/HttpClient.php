<?php

namespace ConfigLeak\Tests\Support;

class HttpClient
{
    private string $cookieJar;

    public function __construct()
    {
        $this->cookieJar = sys_get_temp_dir() . '/configleak_cookies_' . bin2hex(random_bytes(8)) . '.txt';
    }

    /** @return array{status:int, body:string, headers:array<string,string>} */
    public function get(string $url, array $headers = []): array
    {
        return $this->request('GET', $url, null, $headers);
    }

    /** @return array{status:int, body:string, headers:array<string,string>} */
    public function post(string $url, array $fields = [], array $headers = []): array
    {
        return $this->request('POST', $url, http_build_query($fields), $headers);
    }

    private function request(string $method, string $url, ?string $body, array $headers): array
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        curl_setopt($ch, CURLOPT_COOKIEJAR, $this->cookieJar);
        curl_setopt($ch, CURLOPT_COOKIEFILE, $this->cookieJar);
        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }
        $formattedHeaders = [];
        foreach ($headers as $name => $value) {
            $formattedHeaders[] = "{$name}: {$value}";
        }
        curl_setopt($ch, CURLOPT_HTTPHEADER, $formattedHeaders);

        $raw = curl_exec($ch);
        if ($raw === false) {
            throw new \RuntimeException('curl request failed: ' . curl_error($ch));
        }
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        curl_close($ch);

        $rawHeaders = substr($raw, 0, $headerSize);
        $responseBody = substr($raw, $headerSize);

        $responseHeaders = [];
        foreach (explode("\r\n", trim($rawHeaders)) as $line) {
            if (str_contains($line, ':')) {
                [$name, $value] = explode(':', $line, 2);
                $responseHeaders[strtolower(trim($name))] = trim($value);
            }
        }

        return ['status' => $status, 'body' => $responseBody, 'headers' => $responseHeaders];
    }

    public function __destruct()
    {
        if (file_exists($this->cookieJar)) {
            unlink($this->cookieJar);
        }
    }
}
