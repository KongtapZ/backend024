import { Client } from 'pg';
import dotenv from 'dotenv';

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
//-------------------------------------------------------------------------------------
export async function GET(request, { params }) {
  const { id } = params;
    try {
      const result = await client.query('SELECT * FROM tbl_users WHERE id = $1', [id]);
      //return new Response(JSON.stringify({ message: "GET DATA OK"}), {
      return new Response(JSON.stringify(result.rows), {  
        status: 200,
        headers: { 
          ...corsHeaders,
          "Content-Type": "application/json" },
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: "Internal Server Error" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
}
export async function PUT(request,{params}) {
  try {
    const { id, firstname, lastname, username, password } = await request.json();
    const hashedPassword = await bcrypt.hash(password, 10);
    const res = await client.query('UPDATE tbl_users SET firstname = $1, lastname = $2, useranme = $3, password = $4 WHERE id = $5 RETURNING *', [firstname, lastname, username, hashedPassword, id]);
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

//-------------------------------------------------------------------------------------
export async function DELETE(request, { params }) {
  const { id } = params;
  try {
  const res = await client.query('DELETE FROM tbl_users WHERE id = $1 RETURNING *', [id]);
  if (res.rows.length === 0) {
  return new Response(JSON.stringify({ error: 'User not found' }), {
  status: 404,
  headers: { 'Content-Type': 'application/json' },
  });
  }
  return new Response(JSON.stringify(res.rows[0]), {
  status: 200,
  headers: { 'Content-Type': 'application/json' },
  });
  } catch (error) {
  console.error(error);
  return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
  status: 500,
  headers: { 'Content-Type': 'application/json' },
  });
  }
  }