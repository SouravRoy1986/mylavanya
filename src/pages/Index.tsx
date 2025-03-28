
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import Hero from "@/components/sections/Hero";
import HowItWorks from "@/components/sections/HowItWorks";
import Testimonials from "@/components/sections/Testimonials";
import BookingBanner from "@/components/sections/BookingBanner";
import AuthModal from "@/components/auth/AuthModal";
import MainLayout from "@/components/layout/MainLayout";

const Index = () => {
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
  const navigate = useNavigate();

  // Log to confirm Index is being loaded
  console.log("Index page rendering");

  return (
    <MainLayout>
      <Hero 
        onBookNow={() => navigate("/services")}
        onLogin={() => setIsAuthModalOpen(true)}
      />
      <HowItWorks />
      <BookingBanner onBookNow={() => navigate("/services")} />
      <Testimonials />
      
      <AuthModal 
        isOpen={isAuthModalOpen}
        onClose={() => setIsAuthModalOpen(false)}
      />
    </MainLayout>
  );
};

export default Index;
