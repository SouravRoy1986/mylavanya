export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  public: {
    Tables: {
      ArtistApplication: {
        Row: {
          application_date: string | null
          branch_name: string | null
          course_knowledge: Json | null
          created_at: string
          date_of_birth: string | null
          educational_qualification: string | null
          full_address: string | null
          full_name: string
          gender: string | null
          guardian_contact_no: string | null
          guardian_name: string | null
          has_job_experience: boolean | null
          id: string
          job_experience_years: number | null
          job_type: string | null
          landmark: string | null
          marital_status: string | null
          other_job_description: string | null
          phone_no: string
          pin_code: string | null
          relationship_with_guardian: string | null
          status: string | null
          trainer_feedback: string | null
          trainer_name: string | null
          training_required: boolean | null
          training_requirements: string | null
          updated_at: string
        }
        Insert: {
          application_date?: string | null
          branch_name?: string | null
          course_knowledge?: Json | null
          created_at?: string
          date_of_birth?: string | null
          educational_qualification?: string | null
          full_address?: string | null
          full_name: string
          gender?: string | null
          guardian_contact_no?: string | null
          guardian_name?: string | null
          has_job_experience?: boolean | null
          id?: string
          job_experience_years?: number | null
          job_type?: string | null
          landmark?: string | null
          marital_status?: string | null
          other_job_description?: string | null
          phone_no: string
          pin_code?: string | null
          relationship_with_guardian?: string | null
          status?: string | null
          trainer_feedback?: string | null
          trainer_name?: string | null
          training_required?: boolean | null
          training_requirements?: string | null
          updated_at?: string
        }
        Update: {
          application_date?: string | null
          branch_name?: string | null
          course_knowledge?: Json | null
          created_at?: string
          date_of_birth?: string | null
          educational_qualification?: string | null
          full_address?: string | null
          full_name?: string
          gender?: string | null
          guardian_contact_no?: string | null
          guardian_name?: string | null
          has_job_experience?: boolean | null
          id?: string
          job_experience_years?: number | null
          job_type?: string | null
          landmark?: string | null
          marital_status?: string | null
          other_job_description?: string | null
          phone_no?: string
          pin_code?: string | null
          relationship_with_guardian?: string | null
          status?: string | null
          trainer_feedback?: string | null
          trainer_name?: string | null
          training_required?: boolean | null
          training_requirements?: string | null
          updated_at?: string
        }
        Relationships: []
      }
      ArtistMST: {
        Row: {
          Active: boolean | null
          ArtistEmpCode: string | null
          ArtistFirstName: string | null
          Artistgrp: string | null
          ArtistId: number
          ArtistLastName: string | null
          ArtistPhno: number | null
          ArtistRating: number | null
          created_at: string
          emailid: string
          password: string | null
          Source: string | null
          userid: string | null
          uuid: string
        }
        Insert: {
          Active?: boolean | null
          ArtistEmpCode?: string | null
          ArtistFirstName?: string | null
          Artistgrp?: string | null
          ArtistId?: number
          ArtistLastName?: string | null
          ArtistPhno?: number | null
          ArtistRating?: number | null
          created_at?: string
          emailid: string
          password?: string | null
          Source?: string | null
          userid?: string | null
          uuid?: string
        }
        Update: {
          Active?: boolean | null
          ArtistEmpCode?: string | null
          ArtistFirstName?: string | null
          Artistgrp?: string | null
          ArtistId?: number
          ArtistLastName?: string | null
          ArtistPhno?: number | null
          ArtistRating?: number | null
          created_at?: string
          emailid?: string
          password?: string | null
          Source?: string | null
          userid?: string | null
          uuid?: string
        }
        Relationships: []
      }
      BannerImageMST: {
        Row: {
          created_at: string
          id: number
          image_url: string
          status: boolean
          uploaded_by: string
        }
        Insert: {
          created_at?: string
          id?: number
          image_url: string
          status?: boolean
          uploaded_by: string
        }
        Update: {
          created_at?: string
          id?: number
          image_url?: string
          status?: boolean
          uploaded_by?: string
        }
        Relationships: []
      }
      BookMST: {
        Row: {
          Address: string | null
          ArtistId: number | null
          AssignedBY: string | null
          AssignedByUser: string | null
          Assignedto: string | null
          AssignedToEmpCode: string | null
          AssingnedON: string | null
          Booking_date: string | null
          Booking_NO: number | null
          booking_time: string | null
          created_at: string
          email: string | null
          id: number
          jobno: number | null
          name: string | null
          Phone_no: number | null
          Pincode: number | null
          price: number | null
          Product: number | null
          ProductName: string | null
          Purpose: string | null
          Qty: number | null
          Scheme: string | null
          ServiceName: string | null
          Status: string | null
          StatusUpdated: string | null
          SubService: string | null
          uuid: string | null
        }
        Insert: {
          Address?: string | null
          ArtistId?: number | null
          AssignedBY?: string | null
          AssignedByUser?: string | null
          Assignedto?: string | null
          AssignedToEmpCode?: string | null
          AssingnedON?: string | null
          Booking_date?: string | null
          Booking_NO?: number | null
          booking_time?: string | null
          created_at?: string
          email?: string | null
          id?: number
          jobno?: number | null
          name?: string | null
          Phone_no?: number | null
          Pincode?: number | null
          price?: number | null
          Product?: number | null
          ProductName?: string | null
          Purpose?: string | null
          Qty?: number | null
          Scheme?: string | null
          ServiceName?: string | null
          Status?: string | null
          StatusUpdated?: string | null
          SubService?: string | null
          uuid?: string | null
        }
        Update: {
          Address?: string | null
          ArtistId?: number | null
          AssignedBY?: string | null
          AssignedByUser?: string | null
          Assignedto?: string | null
          AssignedToEmpCode?: string | null
          AssingnedON?: string | null
          Booking_date?: string | null
          Booking_NO?: number | null
          booking_time?: string | null
          created_at?: string
          email?: string | null
          id?: number
          jobno?: number | null
          name?: string | null
          Phone_no?: number | null
          Pincode?: number | null
          price?: number | null
          Product?: number | null
          ProductName?: string | null
          Purpose?: string | null
          Qty?: number | null
          Scheme?: string | null
          ServiceName?: string | null
          Status?: string | null
          StatusUpdated?: string | null
          SubService?: string | null
          uuid?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "BookMST_AssignedToEmpCode_fkey"
            columns: ["AssignedToEmpCode"]
            isOneToOne: false
            referencedRelation: "ArtistMST"
            referencedColumns: ["ArtistEmpCode"]
          },
        ]
      }
      categories: {
        Row: {
          category_id: number
          category_name: string
          created_at: string | null
          description: string | null
          updated_at: string | null
        }
        Insert: {
          category_id?: number
          category_name: string
          created_at?: string | null
          description?: string | null
          updated_at?: string | null
        }
        Update: {
          category_id?: number
          category_name?: string
          created_at?: string | null
          description?: string | null
          updated_at?: string | null
        }
        Relationships: []
      }
      FaqMST: {
        Row: {
          active: boolean | null
          answer: string | null
          created_at: string
          id: number
          question: string | null
        }
        Insert: {
          active?: boolean | null
          answer?: string | null
          created_at?: string
          id?: number
          question?: string | null
        }
        Update: {
          active?: boolean | null
          answer?: string | null
          created_at?: string
          id?: number
          question?: string | null
        }
        Relationships: []
      }
      MemberMST: {
        Row: {
          ChildrenDetails: Json | null
          HasChildren: boolean | null
          id: number
          MaritalStatus: boolean | null
          MemberAdress: string | null
          MemberDOB: string | null
          MemberEmailId: string | null
          MemberFirstName: string | null
          MemberLastName: string | null
          MemberPhNo: string | null
          MemberPincode: string | null
          MemberSex: string | null
          MemberStatus: boolean | null
          NumberOfChildren: number | null
          password: string | null
          SpouseName: string | null
          uuid: string
        }
        Insert: {
          ChildrenDetails?: Json | null
          HasChildren?: boolean | null
          id?: number
          MaritalStatus?: boolean | null
          MemberAdress?: string | null
          MemberDOB?: string | null
          MemberEmailId?: string | null
          MemberFirstName?: string | null
          MemberLastName?: string | null
          MemberPhNo?: string | null
          MemberPincode?: string | null
          MemberSex?: string | null
          MemberStatus?: boolean | null
          NumberOfChildren?: number | null
          password?: string | null
          SpouseName?: string | null
          uuid?: string
        }
        Update: {
          ChildrenDetails?: Json | null
          HasChildren?: boolean | null
          id?: number
          MaritalStatus?: boolean | null
          MemberAdress?: string | null
          MemberDOB?: string | null
          MemberEmailId?: string | null
          MemberFirstName?: string | null
          MemberLastName?: string | null
          MemberPhNo?: string | null
          MemberPincode?: string | null
          MemberSex?: string | null
          MemberStatus?: boolean | null
          NumberOfChildren?: number | null
          password?: string | null
          SpouseName?: string | null
          uuid?: string
        }
        Relationships: []
      }
      notifications: {
        Row: {
          booking_id: number
          booking_no: string
          change_type: string
          created_at: string
          id: number
          is_read: boolean
          message: string
          recipient_email: string
          viewed_by: Json | null
        }
        Insert: {
          booking_id: number
          booking_no: string
          change_type: string
          created_at?: string
          id?: number
          is_read?: boolean
          message: string
          recipient_email: string
          viewed_by?: Json | null
        }
        Update: {
          booking_id?: number
          booking_no?: string
          change_type?: string
          created_at?: string
          id?: number
          is_read?: boolean
          message?: string
          recipient_email?: string
          viewed_by?: Json | null
        }
        Relationships: []
      }
      PriceMST: {
        Row: {
          active: boolean | null
          Category: string | null
          created_at: string | null
          Description: string | null
          Discount: number | null
          imageUrl: string | null
          NetPayable: number | null
          Price: number | null
          prod_id: number
          ProductName: string | null
          Scheme: string | null
          Services: string | null
          SubCategory: string | null
          Subservice: string | null
          uuid: string
        }
        Insert: {
          active?: boolean | null
          Category?: string | null
          created_at?: string | null
          Description?: string | null
          Discount?: number | null
          imageUrl?: string | null
          NetPayable?: number | null
          Price?: number | null
          prod_id?: number
          ProductName?: string | null
          Scheme?: string | null
          Services?: string | null
          SubCategory?: string | null
          Subservice?: string | null
          uuid?: string
        }
        Update: {
          active?: boolean | null
          Category?: string | null
          created_at?: string | null
          Description?: string | null
          Discount?: number | null
          imageUrl?: string | null
          NetPayable?: number | null
          Price?: number | null
          prod_id?: number
          ProductName?: string | null
          Scheme?: string | null
          Services?: string | null
          SubCategory?: string | null
          Subservice?: string | null
          uuid?: string
        }
        Relationships: []
      }
      service_otps: {
        Row: {
          booking_id: number
          created_at: string
          expires_at: string
          id: number
          otp_code: string
          phone_number: string
          status_type: string
          verified: boolean
        }
        Insert: {
          booking_id: number
          created_at?: string
          expires_at: string
          id?: number
          otp_code: string
          phone_number: string
          status_type: string
          verified?: boolean
        }
        Update: {
          booking_id?: number
          created_at?: string
          expires_at?: string
          id?: number
          otp_code?: string
          phone_number?: string
          status_type?: string
          verified?: boolean
        }
        Relationships: []
      }
      service_sessions: {
        Row: {
          artist_id: string | null
          created_at: string
          product_id: number | null
          service_complete_time: string | null
          service_id: string
          service_start_time: string | null
          session_id: string
          status: string | null
          total_service_duration: unknown | null
          updated_at: string
        }
        Insert: {
          artist_id?: string | null
          created_at?: string
          product_id?: number | null
          service_complete_time?: string | null
          service_id: string
          service_start_time?: string | null
          session_id?: string
          status?: string | null
          total_service_duration?: unknown | null
          updated_at?: string
        }
        Update: {
          artist_id?: string | null
          created_at?: string
          product_id?: number | null
          service_complete_time?: string | null
          service_id?: string
          service_start_time?: string | null
          session_id?: string
          status?: string | null
          total_service_duration?: unknown | null
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "fk_service_sessions_artist_id"
            columns: ["artist_id"]
            isOneToOne: false
            referencedRelation: "ArtistMST"
            referencedColumns: ["emailid"]
          },
          {
            foreignKeyName: "fk_service_sessions_product_id"
            columns: ["product_id"]
            isOneToOne: false
            referencedRelation: "PriceMST"
            referencedColumns: ["prod_id"]
          },
          {
            foreignKeyName: "fk_service_sessions_service_id"
            columns: ["service_id"]
            isOneToOne: false
            referencedRelation: "BookMST"
            referencedColumns: ["uuid"]
          },
        ]
      }
      statusmst: {
        Row: {
          active: boolean
          created_at: string
          description: string | null
          id: number
          status_code: string
          status_name: string
        }
        Insert: {
          active?: boolean
          created_at?: string
          description?: string | null
          id?: number
          status_code: string
          status_name: string
        }
        Update: {
          active?: boolean
          created_at?: string
          description?: string | null
          id?: number
          status_code?: string
          status_name?: string
        }
        Relationships: []
      }
      sub_categories: {
        Row: {
          category_id: number
          created_at: string | null
          description: string | null
          sub_category_id: number
          sub_category_name: string
          updated_at: string | null
        }
        Insert: {
          category_id: number
          created_at?: string | null
          description?: string | null
          sub_category_id?: number
          sub_category_name: string
          updated_at?: string | null
        }
        Update: {
          category_id?: number
          created_at?: string | null
          description?: string | null
          sub_category_id?: number
          sub_category_name?: string
          updated_at?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "fk_parent_category"
            columns: ["category_id"]
            isOneToOne: false
            referencedRelation: "categories"
            referencedColumns: ["category_id"]
          },
        ]
      }
      UserMST: {
        Row: {
          active: boolean
          email_id: string | null
          FirstName: string | null
          id: number
          LastName: string | null
          password: string | null
          PhoneNo: number | null
          role: string | null
          uuid: string
        }
        Insert: {
          active?: boolean
          email_id?: string | null
          FirstName?: string | null
          id?: number
          LastName?: string | null
          password?: string | null
          PhoneNo?: number | null
          role?: string | null
          uuid?: string
        }
        Update: {
          active?: boolean
          email_id?: string | null
          FirstName?: string | null
          id?: number
          LastName?: string | null
          password?: string | null
          PhoneNo?: number | null
          role?: string | null
          uuid?: string
        }
        Relationships: []
      }
      wishlist: {
        Row: {
          created_at: string | null
          id: number
          service_id: number
          user_id: number
        }
        Insert: {
          created_at?: string | null
          id?: number
          service_id: number
          user_id: number
        }
        Update: {
          created_at?: string | null
          id?: number
          service_id?: number
          user_id?: number
        }
        Relationships: [
          {
            foreignKeyName: "wishlist_service_id_fkey"
            columns: ["service_id"]
            isOneToOne: false
            referencedRelation: "PriceMST"
            referencedColumns: ["prod_id"]
          },
          {
            foreignKeyName: "wishlist_user_id_fkey"
            columns: ["user_id"]
            isOneToOne: false
            referencedRelation: "MemberMST"
            referencedColumns: ["id"]
          },
        ]
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      add_to_wishlist: {
        Args: { service_id_param: number; user_id_param: string }
        Returns: undefined
      }
      create_service_otps_table: {
        Args: Record<PropertyKey, never>
        Returns: undefined
      }
      get_booking_counts_by_status: {
        Args: Record<PropertyKey, never>
        Returns: {
          status: string
          count: number
        }[]
      }
      get_revenue_by_service: {
        Args: Record<PropertyKey, never>
        Returns: {
          service_name: string
          total_revenue: number
        }[]
      }
      get_table_columns: {
        Args: { table_name: string }
        Returns: {
          column_name: string
          data_type: string
        }[]
      }
      get_user_wishlist: {
        Args: { user_uuid: string }
        Returns: {
          id: number
          user_id: string
          service_id: number
          created_at: string
          service_name: string
          service_price: number
          service_category: string
          service_description: string
        }[]
      }
      remove_from_wishlist: {
        Args: { wishlist_id_param: number; user_id_param: string }
        Returns: undefined
      }
    }
    Enums: {
      [_ in never]: never
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DefaultSchema = Database[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof Database },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof Database
  }
    ? keyof (Database[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        Database[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends { schema: keyof Database }
  ? (Database[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      Database[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof Database },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof Database
  }
    ? keyof Database[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends { schema: keyof Database }
  ? Database[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof Database },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof Database
  }
    ? keyof Database[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends { schema: keyof Database }
  ? Database[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof Database },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof Database
  }
    ? keyof Database[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends { schema: keyof Database }
  ? Database[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof Database },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof Database
  }
    ? keyof Database[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends { schema: keyof Database }
  ? Database[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {},
  },
} as const
