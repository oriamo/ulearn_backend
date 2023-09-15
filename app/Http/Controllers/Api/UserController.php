<?php

namespace App\Http\Controllers\Api;

use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Carbon\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class UserController extends Controller
{
    /**
     * Create User
     * @param Request $request
     * @return User 
     */
    public function createUser(Request $request)
    {
        try {
            //we4 try to validate the information provided by the client before adding the user to the database 
            $validateUser = Validator::make($request->all(), 
            [
                'avatar' => 'required',
                'type'   =>  'required',
                'open_id' => 'required',
                'name' => 'required',
                'email' => 'required|email|unique:users,email',
            
            ]);
            //if validation fails return error
            if($validateUser->fails()){
                return response()->json([
                    'status' => false,
                    'message' => 'validation error',
                    'errors' => $validateUser->errors()
                ], 401);
            }
            

            //valoidated will have all user vales that we want to save in the database 
            $validated = $validateUser->Validated();

            $map=[];
            $map['type'] = $validated['type'];
            $map['open_id'] = $validated['open_id'];

            //Queries the database to see if a user with similar credentials already exists
            $user = User::where($map)->first(); 
            

            //this run if there is no macth from the querry 
            //if its empty then the user hasnt been in the database before
            if(empty($user->id)){
                //this is token is our user id 
                $validated["token"]=md5(uniqid().rand(10000,99999));
                $validated['created_at'] = Carbon::now();
                //inserts the data into the database and retruns trhe id of the row 
                $userId = User::insertGetId($validated);
                //queries the database to get all the information about th ejust added user from the database 
                $userInfo = User::where('id', '=', $userId );
                //getting an acess token for the user 
                $accessToken = $userInfo->createToken(uniqid())->plainTextToken;

                $userInfo->access_token  = $accessToken;

                return response()->json([
                    'status' => true,
                    'message' => 'User Created Successfully',
                    'data' => $userInfo
                ], 200);


            }
            return response()->json([
                'status' => true,
                'message' => 'User Created Successfully',
                'token' => $user->createToken("API TOKEN")->plainTextToken
            ], 200);

        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }

    /**
     * Login The User
     * @param Request $request
     * @return User
     */
    public function loginUser(Request $request)
    {
        try {
            $validateUser = Validator::make($request->all(), 
            [
                'email' => 'required|email',
                'password' => 'required'
            ]);

            if($validateUser->fails()){
                return response()->json([
                    'status' => false,
                    'message' => 'validation error',
                    'errors' => $validateUser->errors()
                ], 401);
            }

            if(!Auth::attempt($request->only(['email', 'password']))){
                return response()->json([
                    'status' => false,
                    'message' => 'Email & Password does not match with our record.',
                ], 401);
            }

            $user = User::where('email', $request->email)->first();

            return response()->json([
                'status' => true,
                'message' => 'User Logged In Successfully',
                'token' => $user->createToken("API TOKEN")->plainTextToken
            ], 200);

        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }
}