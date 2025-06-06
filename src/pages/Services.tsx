
import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import ServiceList from "@/components/services/ServiceList";
import Navbar from "@/components/layout/Navbar";
import Footer from "@/components/layout/Footer";
import { supabase } from "@/integrations/supabase/client";
import { Loader } from "lucide-react";

const Services = () => {
  const [selectedCategory, setSelectedCategory] = useState<string>("all");
  const [categories, setCategories] = useState<Array<{ id: string, name: string }>>([
    { id: "all", name: "All Services" }
  ]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  // Fetch categories from database
  useEffect(() => {
    const fetchCategories = async () => {
      setLoading(true);
      try {
        // Query unique categories from the PriceMST table
        const { data, error } = await supabase
          .from('PriceMST')
          .select('Category')
          .eq('active', true)
          .not('Category', 'is', null)
          .order('prod_id', { ascending: true });

        if (error) {
          throw error;
        }

        if (data && data.length > 0) {
          // Extract unique categories
          const uniqueCategories = [...new Set(data.map(item => item.Category))];
          
          // Create the category array with "All Services" as the first option
          const categoryOptions = [
            { id: "all", name: "All Services" },
            ...uniqueCategories.map(category => ({
              id: category || "", 
              name: category || "Uncategorized"
            }))
          ];
          
          setCategories(categoryOptions);
        }
      } catch (error) {
        console.error("Error fetching categories:", error);
      } finally {
        setLoading(false);
      }
    };

    fetchCategories();
  }, []);

  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />
      <div className="pt-24 flex-grow">
        <div className="bg-gradient-to-r from-violet-100 to-purple-50 py-12">
          <div className="container mx-auto px-4 sm:px-6 lg:px-8">
            <h1 className="text-3xl font-bold text-gray-900 md:text-4xl">Our Beauty Services</h1>
            <p className="mt-2 text-lg text-gray-600">
              Professional beauty services for weddings and special events
            </p>
            
            {/* Category filters */}
            {loading ? (
              <div className="flex justify-center items-center mt-6 py-4">
                <Loader className="h-5 w-5 animate-spin text-primary mr-2" />
                <span>Loading categories...</span>
              </div>
            ) : (
              <div className="mt-6 flex flex-wrap gap-2">
                {categories.map(category => (
                  <button
                    key={category.id}
                    className={`px-4 py-2 rounded-full text-sm font-medium transition-colors
                      ${selectedCategory === category.id 
                        ? 'bg-primary text-white shadow-sm' 
                        : 'bg-white/70 text-gray-700 hover:bg-white'}`}
                    onClick={() => setSelectedCategory(category.id)}
                  >
                    {category.name}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
        
        <div className="container mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <ServiceList categoryFilter={selectedCategory !== "all" ? selectedCategory : undefined} />
        </div>
      </div>
      <Footer />
    </div>
  );
};

export default Services;
