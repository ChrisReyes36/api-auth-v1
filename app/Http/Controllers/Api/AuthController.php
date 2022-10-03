<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $data = $request->all();
        // Validación de datos
        $validator = Validator::make($data, [
            'name' => 'required|string',
            'email' => 'required|string|email|unique:users',
            'password' => 'required|string|confirmed',
        ]);
        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Error de validación',
                'errors' => $validator->errors()
            ], 400);
        }
        // Crear usuario
        $user = new User([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
        ]);
        $user->save();
        // Retornar respuesta
        return response()->json([
            'message' => 'Usuario creado exitosamente',
            'user' => $user,
        ], 201);
    }

    public function login(Request $request)
    {
        $data = $request->all();
        // Validación de datos
        $validator = Validator::make($data, [
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);
        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Error de validación',
                'errors' => $validator->errors()
            ], 400);
        }
        // Validar credenciales
        $credentials = request(['email', 'password']);
        if (!Auth::attempt($credentials)) {
            return response()->json([
                'success' => false,
                'message' => 'Credenciales inválidas',
            ], 401);
        }
        // Retornar respuesta
        $user = Auth::user();
        // $token = $user->createToken('token');
        // $token->accessToken->expires_at = Carbon::now()->addHours(3);
        // $token->accessToken->save();
        // return response()->json([
        //     'success' => true,
        //     'message' => 'Credenciales válidas',
        //     'user' => $user,
        //     'token' => $token->plainTextToken,
        //     'expires_at' => Carbon::parse(
        //         $token->accessToken->expires_at
        //     )->toDateTimeString(),
        // ], 200);
        $token = $user->createToken('token')->plainTextToken;
        $cookie = cookie('cookie_token', $token, 60 * 24);
        return response()->json([
            'success' => true,
            'message' => 'Credenciales válidas',
            'user' => $user,
            'token' => $token,
        ], 200)->withCookie($cookie);
    }

    public function user()
    {
        return response()->json([
            'success' => true,
            'user' => Auth::user(),
        ], 200);
    }

    public function logout(Request $request)
    {
        $token_id = Auth::user()->currentAccessToken()->id;
        Auth::user()->tokens()->where('id', $token_id)->delete();
        $cookie = Cookie::forget('cookie_token');
        return response()->json([
            'success' => true,
            'message' => 'Sesión cerrada',
        ], 200)->withCookie($cookie);
    }

    public function users()
    {
        return response()->json([
            'success' => true,
            'users' => User::all(),
        ], 200);
    }
}
