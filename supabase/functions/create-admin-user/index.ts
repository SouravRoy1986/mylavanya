import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.49.1';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

serve(async (req) => {
  // Handle CORS preflight requests
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    // Get JWT token from Authorization header
    const authHeader = req.headers.get('Authorization');
    if (!authHeader) {
      throw new Error('Missing Authorization header');
    }

    // Create service role client for admin operations
    const supabaseAdmin = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
    );

    // Create anon client to verify JWT and get user
    const supabaseAnon = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_ANON_KEY') ?? ''
    );

    // Verify JWT and get user
    const { data: { user }, error: authError } = await supabaseAnon.auth.getUser(
      authHeader.replace('Bearer ', '')
    );

    if (authError || !user) {
      throw new Error('Invalid or expired token');
    }

    // Check if user has superadmin role
    const { data: userData, error: roleError } = await supabaseAdmin
      .from('UserMST')
      .select('role, active')
      .eq('id', user.id)
      .eq('active', true)
      .single();

    if (roleError || !userData || userData.role !== 'superadmin') {
      throw new Error('Insufficient permissions - superadmin role required');
    }

    // Parse request body
    const { email, firstName, lastName, role, phoneNo } = await req.json();

    if (!email || !firstName || !lastName || !role) {
      throw new Error('Missing required fields: email, firstName, lastName, role');
    }

    console.log('Creating admin user:', { email, firstName, lastName, role, phoneNo });

    // Create user in auth.users table
    const { data: authUser, error: createError } = await supabaseAdmin.auth.admin.createUser({
      email,
      phone: phoneNo ? phoneNo.toString() : undefined,
      phone_confirm: false, // Keep phone_confirmed_at as null
      user_metadata: {
        firstName,
        lastName,
        role
      }
    });

    if (createError || !authUser.user) {
      console.error('Error creating auth user:', createError);
      throw new Error(`Failed to create auth user: ${createError?.message}`);
    }

    console.log('Auth user created successfully:', authUser.user.id);

    // Create user in UserMST table
    const { error: userMSTError } = await supabaseAdmin
      .from('UserMST')
      .insert({
        id: authUser.user.id,
        email_id: email,
        FirstName: firstName,
        LastName: lastName,
        role: role,
        PhoneNo: phoneNo ? parseInt(phoneNo.toString()) : null,
        active: true
      });

    if (userMSTError) {
      console.error('Error creating UserMST record:', userMSTError);
      
      // Rollback: Delete the auth user
      try {
        await supabaseAdmin.auth.admin.deleteUser(authUser.user.id);
        console.log('Rollback: Auth user deleted');
      } catch (rollbackError) {
        console.error('Rollback failed:', rollbackError);
      }
      
      throw new Error(`Failed to create user record: ${userMSTError.message}`);
    }

    console.log('UserMST record created successfully');

    return new Response(
      JSON.stringify({ 
        success: true, 
        message: 'User created successfully',
        userId: authUser.user.id 
      }),
      {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        status: 200,
      }
    );

  } catch (error) {
    console.error('Error in create-admin-user function:', error);
    return new Response(
      JSON.stringify({ 
        error: error.message || 'An unexpected error occurred' 
      }),
      {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      }
    );
  }
});