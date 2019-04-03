<?php

namespace App\Http\Controllers;

use App\User;
use http\Env\Response;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class UserController extends Controller
{
    //Login function
    public function authenticate(Request $request)
    {
        $credentials = $request->only('email', 'password'); //取出request的email及password
        $token = JWTAuth::attempt($credentials);    //透過JWTAuth::attempt來驗證email及password
        try {
            if (! $token) {    //如果驗證失敗，回傳顯示無效
                return response()->json(['error' => 'invalid_credentials'], 400);
            }
        } catch (\JWTException $e) {
            return response()->json(['error' => 'could_not_create_token'], 500);
        }

        return response()->json(['token' => $token]);
    }

    //User register
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6|confirmed',
        ]);

        if($validator->fails()){
            return response()->json([
                'error message' => $validator->errors(),
                'erroe code' => 400]); //如果輸入的資料不符合規範，則印出error message
        }

        $user = User::create([
            'name' => $request->get('name'),
            'email' => $request->get('email'),
            'password' => Hash::make($request->get('password')),
        ]);

        $token = JWTAuth::fromUser($user);

        return response()->json([
            'data' => $user,
            'token' => $token,
            'error code' => 201]);
    }

    public function getAuthenticatedUser()
    {
        try {

            if (! $user = JWTAuth::parseToken()->authenticate()) {
                return response()->json(['user not found'], 404);
            }

        } catch (Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {

            return response()->json(['token expired'], $e->getStatusCode());

        } catch (Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {

            return response()->json(['token invalid'], $e->getStatusCode());

        } catch (Tymon\JWTAuth\Exceptions\JWTException $e) {

            return response()->json(['token absent'], $e->getStatusCode());

        }


        return response()->json(compact('user'));
    }

    public function update(Request $request)
    {
        try {

            if (! $user = JWTAuth::parseToken()->authenticate()) {
                return response()->json(['user not found'], 404);
            }

        } catch (Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {

            return response()->json(['token expired'], $e->getStatusCode());

        } catch (Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {

            return response()->json(['token invalid'], $e->getStatusCode());

        } catch (Tymon\JWTAuth\Exceptions\JWTException $e) {

            return response()->json(['token absent'], $e->getStatusCode());

        }

        $data = User::find($request['id']);

        if (empty($data)) {
            throw new \Exception('data not found', 404);
        }
        return $data;

        $validator = Validator::make($request->all(), [
            'name' => 'string|max:255',
            'email' => 'string|email|max:255|unique:users',
            'password' => 'string|min:6|confirmed',
        ]);

        if ($validator->failed()) {
            return response()->json([
                'error message' => $validator->errors(),
                'error code' => 400]);
        }


    }
}
