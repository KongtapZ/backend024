import { NextResponse } from "next/server";
import { Client } from "pg";
import dotenv from "dotenv";
import bcrypt from 'bcrypt'; 
import jwt from 'jsonwebtoken'; 

dotenv.config();

const client = new Client({
  connectionString: process.env.DATABASE_URL,
});

client.connect(err => {
  if (err) {
    console.error('Database connection error:', err.stack);
  } else {
    console.log('Database connected');
  }
});

export async function POST(request) {
  try {
    let requestData;
    try {
      requestData = await request.json();
      console.log('Request data:', requestData);
    } catch (error) {
      console.error('Error parsing JSON:', error);
      return new Response(JSON.stringify({ error: 'Invalid JSON' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const { username, password } = requestData;
    
    let res;
    try {
      res = await client.query('SELECT * FROM tbl_users WHERE username = $1', [username]);
      console.log('Database query result:', res.rows);
    } catch (error) {
      console.error('Database query error:', error);
      return new Response(JSON.stringify({ error: 'Database query failed' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    if (res.rows.length === 0) {
      return new Response(JSON.stringify({ error: 'User not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const user = res.rows[0];
    console.log('User found:', user);

    let match;
    try {
      match = await bcrypt.compare(password, user.password);
      console.log('Password match:', match);
    } catch (error) {
      console.error('Error comparing passwords:', error);
      return new Response(JSON.stringify({ error: 'Password comparison failed' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    if (!match) {
      return new Response(JSON.stringify({ error: 'Invalid password' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    let token;
    try {
      token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
      console.log('Generated token:', token);
    } catch (error) {
      console.error('Error generating token:', error);
      return new Response(JSON.stringify({ error: 'Token generation failed' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return new Response(JSON.stringify({ message: 'Login successful', user, token }), {
      status: 200,
      headers: { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('Internal Server Error:', error.message, error.stack);
    return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
      status: 500,
      headers: { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json' },
    });
  }
}
