<?php

namespace App\Http\Controllers;

use App\User;
use App\Http\Requests\RegisterAuthRequest;
use JWTAuth;
use Illuminate\Support\Facades\Auth;
use Illuminate\Http\Request;

class AuthController extends Controller
{
    /**
     * Creates a new AuthController instance.
     * 
     * @return void
     */

    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    /**
     * Get a JWT via given credentials.
     * 
     * @return \Illuminate\Http\JsonResponse
     */

    public function login()
    {
        $credentials = request(['email', 'password']);

        if (! $token = auth()->attempt($credentials)) {
                return response()->json([
                    'status' => 'error',
                    'error' => 'Invalid email or password'
            ], 401);
        }

        return $this->respondWithToken($token);
    }

    /**
     * Register a user with credentials
     * 
     * @return \Illuminate\Http\JsonResponse
     */

    public function register(RegisterAuthRequest $request)
    {
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
        ]);

        $token = auth()->login($user);

        return $this->respondWithToken($token);
    }

    /**
     * Log the user out (Invalidate the token).
     * 
     * @return \Illuminate\Http\JsonResponse
     */

    public function logout(Request $request)
    {
        if(!JWTAuth::invalidate(true)) {
            return response()->json([
                'status' => 'error',
                'error' => 'Error when trying to invalidate token'
            ], 404);
        }

        return response()->json([
            'status' => 'success',
            'message' => 'Successfully logged out'
        ]);
    }

    /**
     * Refresh a token
     * 
     * @return \Illuminate\Http\JsonResponse
     */

    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    /**
     * Get authenticated user from token
     * @return \Illuminate\Http{JsonResponse
     */

    public function getAuthenticatedUser()
    {
        if (! $user = JWTAuth::parseToken()->authenticate()) {
            return response ()->json([
                'status' => 'error',
                'error' => 'user_not_found'
            ], 404);
        }

        return response()->json([
            'status' => 'success',
            'data' => compact('user')
        ]);
    }

    /**
     * Get the token array structure.
     * 
     * @param string $token
     * 
     * @return \Illuminate\Http\JsonResponse
     */
    
    protected function respondWithToken($token)
    {
        return response()->json([
            'status' => 'success',
            'data' => [
                'access_token' => $token,
                'token_type' => 'bearer',
                'expires_in' => auth('api')->factory()->getTTL() * 60
            ]
        ]);
    }
}
