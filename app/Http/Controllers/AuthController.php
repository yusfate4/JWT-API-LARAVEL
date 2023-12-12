<?php

namespace App\Http\Controllers;

// use Auth;
use Illuminate\Http\Request;
use Validator;
use App\Models\User;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function _construct()
    {
        $this->middleware("auth:api", ["except" => ['login', 'register']]);
    }
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users,email',
            'password' => 'required|string|min:6|confirmed',
            'role' => 'required|in:user,admin', // Assuming 'user' and 'admin' are valid roles
        ]);

        // if validator fails
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 400);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
            'role' => $request->role,
        ]);

        $token = JWTAuth::fromUser($user);

        return response()->json(compact('token'));
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [

            'email' => 'required|email',
            'password' => 'required|string|min:6'
        ]);
        // if validator fails
        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }
        if (!$token = auth()->attempt($validator->validated())) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        return $this->createNewToken($token);
    }

    public function createNewToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 30,
            'user' => auth()->user()
        ]);
    }


    /**
     * Get the user profile.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function userProfile(Request $request)
    {
        $user = $request->user();

        $response = [
            'message' => 'User profile retrieved successfully',
            'user' => $user,
        ];

        return response()->json($response, 200);
    }

    /**
     * Get the admin dashboard.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function adminDashboard(Request $request)
    {
        $user = $request->user();


        $response = [
            'message' => 'Admin dashboard retrieved successfully',
            'user' => $user,
        ];

        return response()->json($response, 200);
    }
    public function profile()
    {
        return response()->json(auth()->user());
    }

    public function logout()
    {
        auth()->logout();
        return response()->json([
            'message' => 'User Successfully Logged out',

        ],);
    }
    public function refresh()
    {
        if (Auth::user()->isAdmin()) {
            $token = JWTAuth::refresh();
            return response()->json(compact('token'));
        }

        return response()->json(['error' => 'Unauthorized'], 403);
    }
}
