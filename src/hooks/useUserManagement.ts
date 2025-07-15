
import { useState, useEffect } from "react";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";

interface User {
  id: string | null;
  email_id: string;
  FirstName: string | null;
  LastName: string | null;
  role: string | null;
  active?: boolean;
  PhoneNo?: number | null;
}

export const useUserManagement = () => {
  const { toast } = useToast();
  const [users, setUsers] = useState<User[]>([]);
  const [filteredUsers, setFilteredUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [roleFilter, setRoleFilter] = useState<string>("all");
  const [activeFilter, setActiveFilter] = useState<string>("all");

  const fetchUsers = async () => {
    try {
      setLoading(true);
      const { data, error } = await supabase
        .from('UserMST')
        .select('*')
        .order('email_id', { ascending: true });

      if (error) throw error;
      setUsers((data as User[]) || []);
      setFilteredUsers((data as User[]) || []);
    } catch (error) {
      console.error('Error fetching users:', error);
      toast({
        title: "Failed to load users",
        description: "Please try again later",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  useEffect(() => {
    let result = [...users];
    
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      result = result.filter(
        user => 
          (user.email_id && user.email_id.toLowerCase().includes(query)) ||
          (user.FirstName && user.FirstName.toLowerCase().includes(query)) ||
          (user.LastName && user.LastName.toLowerCase().includes(query))
      );
    }
    
    if (roleFilter !== "all") {
      result = result.filter(user => user.role === roleFilter);
    }
    
    if (activeFilter !== "all") {
      const isActive = activeFilter === "active";
      result = result.filter(user => user.active === isActive);
    }
    
    setFilteredUsers(result);
  }, [users, searchQuery, roleFilter, activeFilter]);

  const clearFilters = () => {
    setSearchQuery("");
    setRoleFilter("all");
    setActiveFilter("all");
  };

  const deleteUser = async (userEmailId: string) => {
    try {
      const { error } = await supabase
        .from('UserMST')
        .delete()
        .eq('email_id', userEmailId);

      if (error) throw error;

      setUsers(users.filter(u => u.email_id !== userEmailId));
      toast({
        title: "User deleted",
        description: "The user has been successfully removed",
      });
    } catch (error) {
      console.error('Error deleting user:', error);
      toast({
        title: "Deletion failed",
        description: "There was a problem deleting the user",
        variant: "destructive"
      });
    }
  };

  const toggleUserStatus = async (userEmailId: string, currentStatus: boolean) => {
    try {
      const newActiveState = !currentStatus;
      const { error } = await supabase
        .from('UserMST')
        .update({ active: newActiveState })
        .eq('email_id', userEmailId);

      if (error) throw error;

      setUsers(users.map(user => 
        user.email_id === userEmailId 
          ? { ...user, active: newActiveState } 
          : user
      ));
      
      const targetUser = users.find(u => u.email_id === userEmailId);
      toast({
        title: newActiveState ? "User activated" : "User deactivated",
        description: `User "${targetUser?.email_id}" has been ${newActiveState ? "activated" : "deactivated"}`,
      });
    } catch (error) {
      console.error('Error updating user active state:', error);
      toast({
        title: "Error",
        description: "Failed to update the user",
        variant: "destructive",
      });
    }
  };

  const saveUser = async (userData: any, isNewUser: boolean, currentUserEmailId?: string) => {
    try {
      if (!userData.email_id) {
        throw new Error("Email is required");
      }

      if (isNewUser) {
        // Call the edge function to create user
        const { data, error } = await supabase.functions.invoke('create-admin-user', {
          body: {
            email: userData.email_id,
            firstName: userData.FirstName || '',
            lastName: userData.LastName || '',
            role: userData.role || 'admin',
            phoneNo: userData.PhoneNo || null
          }
        });

        if (error) {
          console.error('Edge function error:', error);
          throw new Error(error.message || 'Failed to create user');
        }

        if (data?.error) {
          console.error('User creation error:', data.error);
          throw new Error(data.error);
        }

        console.log('User created successfully via edge function:', data);
        
        // Refresh the users list
        await fetchUsers();
        
        toast({
          title: "User created successfully",
          description: "User has been created. They will need to set up their password on first login.",
        });
      } else if (currentUserEmailId) {
        // Update existing user in UserMST only
        const userPayload = {
          email_id: userData.email_id,
          FirstName: userData.FirstName || null,
          LastName: userData.LastName || null,
          role: userData.role || "admin",
          active: userData.active !== undefined ? userData.active : true,
          PhoneNo: userData.PhoneNo || null
        };

        const { error } = await supabase
          .from('UserMST')
          .update(userPayload)
          .eq('email_id', currentUserEmailId);

        if (error) throw error;

        setUsers(users.map(user => 
          user.email_id === currentUserEmailId 
            ? { ...user, ...userPayload } 
            : user
        ));
        
        toast({
          title: "User updated",
          description: "User has been successfully updated",
        });
      }
    } catch (error) {
      console.error('Error saving user:', error);
      toast({
        title: "Save failed",
        description: error instanceof Error ? error.message : "There was a problem saving the user",
        variant: "destructive"
      });
      throw error;
    }
  };

  return {
    users,
    filteredUsers,
    loading,
    searchQuery,
    setSearchQuery,
    roleFilter,
    setRoleFilter,
    activeFilter,
    setActiveFilter,
    clearFilters,
    deleteUser,
    toggleUserStatus,
    saveUser
  };
};
