"use server";
// app/api/route.js
import { Client } from 'pg';
import dotenv from 'dotenv';
// import bcrypt from 'bcrypt';
const bcrypt = require('bcrypt');
dotenv.config();
const client = new Client({
  connectionString: process.env.DATABASE_URL,
});
client.connect();

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

export async function GET() {
  try {
    const result = await client.query('SELECT * FROM tbl_users');
    return new Response(JSON.stringify(result.rows), {
      status: 200,
      headers: {
        ...corsHeaders,
        "Content-Type": "application/json",
        "Cache-Control": "no-cache"
      },
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: "Internal Server Error" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
}

export async function POST(request) {
  try {
    const { firstname, lastname, username, password } = await request.json();
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log(hashedPassword);
    const res = await client.query('INSERT INTO tbl_users (firstname, lastname, username, password) VALUES ($1, $2, $3, $4) RETURNING *', [firstname, lastname, username, hashedPassword]);
    return new Response(JSON.stringify(res.rows[0]), {
      status: 201,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error(error);
    return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
}

export async function PUT(request) {
  try {
    // รับค่าที่ส่งมาจาก client-side
    const { id, firstname, lastname, username, password } = await request.json();

    // แฮชรหัสผ่าน
    const hashedPassword = await bcrypt.hash(password, 10);

    // อัปเดตข้อมูลในฐานข้อมูล
    const res = await client.query(
      'UPDATE tbl_users SET firstname = $1, lastname = $2, username = $3, password = $4 WHERE id = $5 RETURNING *',
      [firstname, lastname, username, hashedPassword, id]
    );

    // ตรวจสอบว่าผลลัพธ์ของการอัปเดตมีแถวที่ถูกเปลี่ยนแปลงหรือไม่
    if (res.rows.length === 0) {
      return new Response(JSON.stringify({ error: 'User not found' }), {
        status: 404,
        headers: { 
          'Access-Control-Allow-Origin': '*', 
          'Content-Type': 'application/json' 
        },
      });
    }

    // ตอบกลับด้วยข้อมูลผู้ใช้ที่ถูกอัปเดต
    return new Response(JSON.stringify(res.rows[0]), {
      status: 200,
      headers: { 
        'Access-Control-Allow-Origin': '*', 
        'Content-Type': 'application/json' 
      },
    });

  } catch (error) {
    console.error('Error during PUT request:', error);

    // ตอบกลับเมื่อเกิดข้อผิดพลาด
    return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
      status: 500,
      headers: { 
        'Access-Control-Allow-Origin': '*', 
        'Content-Type': 'application/json' 
      },
    });
  }
}

export async function DELETE(request) {
  try {
    const { id } = await request.json();
    const res = await client.query('DELETE FROM tbl_users WHERE id = $1 RETURNING *', [id]);
    if (res.rows.length === 0) {
      return new Response(JSON.stringify({ error: 'User not found' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }
    return new Response(JSON.stringify(res.rows[0]), {
      status: 200,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error(error);
    return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
}