<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Bigcommerce\Api\Client as Bigcommerce;
use GuzzleHttp\Client;
use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;

class BigcommerceController extends Controller
{
    
    protected $baseURL;
    protected $clientId;
    protected $clientSecret;

    public function __construct()
    {
        $this->baseURL = env('APP_URL');
        $this->clientId = env('BC_CLIENT_ID');
        $this->clientSecret = env('BC_CLIENT_SECRET');
    }

    public function install(Request $request): RedirectResponse
    {
        $tokenUrl = 'https://login.bigcommerce.com/oauth2/token';

        $guzzle = new Client();
        $response = $guzzle->post($tokenUrl, [
            'form_params' => [
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'code' => $request->input('code'),
                'scope' => $request->input('scope'),
                'context' => $request->input('context'),
                'grant_type' => 'authorization_code',
                'redirect_uri' => $this->baseURL . '/auth/install',
            ],
        ]);

        $statusCode = $response->getStatusCode();
        $data = json_decode($response->getBody(), true);

        if ($statusCode == 200) {
            // Store access token
            $request->session()->put('access_token', $data['access_token']);
        }

        return redirect()->route('bigcommerce.dashboard');
    }

    public function callback(Request $request): RedirectResponse
    {
        $signedPayload = $request->input('signed_payload');
        if (!empty($signedPayload)) {
            // Decode the signed data
            $verifiedSignedRequestData = $this->verifySignedRequest($signedPayload, $request);
            if ($verifiedSignedRequestData !== null) {
                // Store the user data
                $request->session()->put('user_id', $verifiedSignedRequestData['user']['id']);
                $request->session()->put('user_email', $verifiedSignedRequestData['user']['email']);
                $request->session()->put('owner_id', $verifiedSignedRequestData['owner']['id']);
                $request->session()->put('owner_email', $verifiedSignedRequestData['owner']['email']);
                $request->session()->put('store_hash', $verifiedSignedRequestData['context']);  
            }
        }

        return redirect()->route('bigcommerce.dashboard');
    }

    public function dashboard(): View
    {
        return view('dashboard');
    }

    private function verifySignedRequest($signedRequest, $appRequest)
    {
        list($encodedData, $encodedSignature) = explode('.', $signedRequest, 2);

        // decode the data
        $signature = base64_decode($encodedSignature);
        $jsonStr = base64_decode($encodedData);
        $data = json_decode($jsonStr, true);

        // confirm the signature
        $expectedSignature = hash_hmac('sha256', $jsonStr, $this->clientSecret, $raw = false);
        if (!hash_equals($expectedSignature, $signature)) {
            error_log('Bad signed request from BigCommerce!');
            return null;
        }
        return $data;
    }
}
