<?php

namespace App\Http\Controllers\Api;

use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Validator;

class LoginController extends Controller
{
    /**
     * Handle the incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function __invoke(Request $request)
    {
        //set validation
        $validator = Validator::make($request->all(), [
            'email'     => 'required',
            'password'  => 'required'
        ]);

        //if validation fails
        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        //get credentials from request
        $credentials = $request->only('email', 'password');
        $remember = $request->boolean('remember');

        //if auth failed
        if(!$token = JWTAuth::attempt($credentials, ['remember' => $remember])) {
            return response()->json([
                'success' => false,
                'message' => 'Your email or password is wrong!'
            ], 401);
        }

        $user = auth()->user();

        // Check if user is active
        if (!$user->active) {
            return response()->json([
                'success' => false,
                'message' => 'Your account is not active. Please contact the administrator.'
            ], 403);
        }

        $role = '';
        if ($user->hasRole('admin')) {
            $role = 'admin';
        } else if ($user->hasRole('user')) {
            $role = 'user';
        }

        //if auth success
        return response()->json([
            'success' => true,
            'user'    => $user,   
            'role'    => $role, 
            'token'   => $token   
        ], 200);
    }
}