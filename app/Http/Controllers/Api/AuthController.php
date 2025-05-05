<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Mail;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email|unique:users',
            'phone' => 'required|unique:users',
            'password' => 'required|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        $user = User::create([
            'email' => $request->email,
            'phone' => $request->phone,
            'password' => Hash::make($request->password),
        ]);

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'access_token' => $token,
            'token_type' => 'Bearer',
        ]);
    }

    public function login(Request $request)
    {
        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json(['message' => 'Invalid credentials'], 401);
        }

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'access_token' => $token,
            'token_type' => 'Bearer',
        ]);
    }

    public function forgotPassword(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'via' => 'required|in:email,sms',
            'email' => 'required_if:via,email',
            'phone' => 'required_if:via,sms',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        $code = rand(1000, 9999);

        $user = null;
        if ($request->via === 'email') {
            $user = User::where('email', $request->email)->first();
        } else {
            $user = User::where('phone', $request->phone)->first();
        }

        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }

        $user->reset_code = $code;
        $user->save();

        if ($request->via === 'email') {
            // Kirim email (pastikan sudah setup Mail di .env)
            Mail::raw("Kode reset password kamu adalah: $code", function ($message) use ($user) {
                $message->to($user->email)->subject('Reset Password Code');
            });
        } else {
            // Simulasi SMS — untuk implementasi nyata pakai API SMS seperti Twilio
            \Log::info("SMS to {$user->phone}: Kode reset kamu adalah: $code");
        }

        return response()->json(['message' => 'Kode telah dikirim.']);
    }

    public function resetPassword(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email_or_phone' => 'required',
            'code' => 'required|digits:4',
            'new_password' => 'required|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        $user = User::where('email', $request->email_or_phone)
            ->orWhere('phone', $request->email_or_phone)
            ->first();

        if (!$user || $user->reset_code != $request->code) {
            return response()->json(['message' => 'Kode salah atau user tidak ditemukan'], 400);
        }

        $user->password = Hash::make($request->new_password);
        $user->reset_code = null;
        $user->save();

        return response()->json(['message' => 'Password berhasil direset']);
    }

    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();
        return response()->json(['message' => 'Logged out']);
    }
}