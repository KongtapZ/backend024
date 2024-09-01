import { NextResponse } from "next/server";
import { Client } from "pg";
import dotenv from "dotenv";
import bcrypt from 'bcrypt'; 
import jwt from 'jsonwebtoken'; 

dotenv.config();

const client = new Client({
  connectionString: process.env.DATABASE_URL, // ใช้เฉพาะ DATABASE_URL สำหรับการเชื่อมต่อกับฐานข้อมูล
});

client.connect();

export async function POST(request) {
  try {
    const { username, password } = await request.json();
    const res = await client.query('SELECT * FROM tbl_users WHERE username = $1', [username]);

    if (res.rows.length === 0) {
      return new Response(JSON.stringify({ error: 'User not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const user = res.rows[0];
    console.log(user);
    const match = await bcrypt.compare(password, user.password);
    console.log(match);

    if (!match) {
      return new Response(JSON.stringify({ error: 'Invalid password' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    } else {
      // Generate JWT token
      const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });

      return new Response(JSON.stringify({ message: 'Login successful', user, token }), {
        status: 200,
        headers: { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json' },
      });
    }
  } catch (error) {
    console.error(error);
    return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
      status: 500,
      headers: { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json' },
    });
  }
}
