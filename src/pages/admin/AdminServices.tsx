
import { useState, useEffect } from "react";
import { useToast } from "@/hooks/use-toast";
import DashboardLayout from "@/components/dashboard/DashboardLayout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import ProtectedRoute from "@/components/auth/ProtectedRoute";
import { supabase } from "@/integrations/supabase/client";
import { 
  Table, 
  TableBody, 
  TableCell, 
  TableHead, 
  TableHeader, 
  TableRow 
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { Edit, Plus, Trash2, Power, Search, X } from "lucide-react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { useAuth } from "@/context/AuthContext";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ExportButton } from "@/components/ui/export-button";
import { Switch } from "@/components/ui/switch";
import { Form, FormField, FormItem, FormLabel, FormControl, FormMessage } from "@/components/ui/form";
import { useForm } from "react-hook-form";

interface Service {
  prod_id: number;
  Services: string;
  ProductName: string | null;
  Description: string | null;
  Price: number;
  active?: boolean;
  Subservice?: string | null;
  Scheme?: string | null;
  Category?: string | null;
  Discount?: number | null;
  NetPayable?: number | null;
}

const AdminServices = () => {
  const { toast } = useToast();
  const { user } = useAuth();
  const [services, setServices] = useState<Service[]>([]);
  const [filteredServices, setFilteredServices] = useState<Service[]>([]);
  const [loading, setLoading] = useState(true);
  const [openDialog, setOpenDialog] = useState(false);
  const [openDeleteDialog, setOpenDeleteDialog] = useState(false);
  const [openDeactivateDialog, setOpenDeactivateDialog] = useState(false);
  const [isNewService, setIsNewService] = useState(false);
  const [currentService, setCurrentService] = useState<Service | null>(null);
  const [serviceToDelete, setServiceToDelete] = useState<Service | null>(null);
  const [serviceToDeactivate, setServiceToDeactivate] = useState<Service | null>(null);
  
  const [searchQuery, setSearchQuery] = useState("");
  const [activeFilter, setActiveFilter] = useState<string>("all");
  
  const isSuperAdmin = user?.role === 'superadmin';
  
  // Form state
  const [serviceName, setServiceName] = useState("");
  const [subService, setSubService] = useState("");
  const [scheme, setScheme] = useState("");
  const [category, setCategory] = useState("");
  const [serviceDescription, setServiceDescription] = useState("");
  const [servicePrice, setServicePrice] = useState("");
  const [discount, setDiscount] = useState("");
  const [netPayable, setNetPayable] = useState("");
  const [priceFirst, setPriceFirst] = useState(true);
  
  const serviceHeaders = {
    prod_id: 'ID',
    Services: 'Service Name',
    ProductName: 'Product Name',
    Subservice: 'Sub Service',
    Scheme: 'Scheme',
    Category: 'Category',
    Price: 'Price',
    Discount: 'Discount %',
    NetPayable: 'Net Payable',
    Description: 'Description',
    active: 'Status'
  };

  useEffect(() => {
    const fetchServices = async () => {
      try {
        setLoading(true);
        const { data, error } = await supabase
          .from('PriceMST')
          .select('*')
          .order('Services', { ascending: true });

        if (error) throw error;
        setServices(data || []);
        setFilteredServices(data || []);
      } catch (error) {
        console.error('Error fetching services:', error);
        toast({
          title: "Failed to load services",
          description: "Please try again later",
          variant: "destructive"
        });
      } finally {
        setLoading(false);
      }
    };

    fetchServices();
  }, [toast]);

  useEffect(() => {
    let result = [...services];
    
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      result = result.filter(
        service => 
          service.Services.toLowerCase().includes(query) ||
          (service.ProductName && service.ProductName.toLowerCase().includes(query)) ||
          (service.Description && service.Description.toLowerCase().includes(query))
      );
    }
    
    if (activeFilter !== "all") {
      const isActive = activeFilter === "active";
      result = result.filter(service => service.active === isActive);
    }
    
    setFilteredServices(result);
  }, [services, searchQuery, activeFilter]);

  const clearFilters = () => {
    setSearchQuery("");
    setActiveFilter("all");
  };

  const generateProductName = () => {
    const parts = [
      serviceName.trim(),
      subService.trim(),
      scheme.trim()
    ].filter(Boolean);
    
    return parts.join(' - ');
  };

  const handleAddNew = () => {
    setIsNewService(true);
    setCurrentService(null);
    setServiceName("");
    setSubService("");
    setScheme("");
    setCategory("");
    setServiceDescription("");
    setServicePrice("");
    setDiscount("");
    setNetPayable("");
    setPriceFirst(true);
    setOpenDialog(true);
  };

  const handleEdit = (service: Service) => {
    setIsNewService(false);
    setCurrentService(service);
    setServiceName(service.Services || "");
    setSubService(service.Subservice || "");
    setScheme(service.Scheme || "");
    setCategory(service.Category || "");
    setServiceDescription(service.Description || "");
    setServicePrice(service.Price?.toString() || "");
    setDiscount(service.Discount?.toString() || "");
    setNetPayable(service.NetPayable?.toString() || "");
    setPriceFirst(true);
    setOpenDialog(true);
  };

  const handleDelete = (service: Service) => {
    setServiceToDelete(service);
    setOpenDeleteDialog(true);
  };

  const handleDeactivate = (service: Service) => {
    setServiceToDeactivate(service);
    setOpenDeactivateDialog(true);
  };

  const confirmDelete = async () => {
    if (!serviceToDelete) return;

    try {
      const { error } = await supabase
        .from('PriceMST')
        .delete()
        .eq('prod_id', serviceToDelete.prod_id);

      if (error) throw error;

      setServices(services.filter(s => s.prod_id !== serviceToDelete.prod_id));
      toast({
        title: "Service deleted",
        description: "The service has been successfully removed",
      });
      setOpenDeleteDialog(false);
    } catch (error) {
      console.error('Error deleting service:', error);
      toast({
        title: "Deletion failed",
        description: "There was a problem deleting the service",
        variant: "destructive"
      });
    }
  };

  const confirmDeactivate = async () => {
    if (!serviceToDeactivate) return;

    try {
      const newActiveState = !serviceToDeactivate.active;
      const { error } = await supabase
        .from('PriceMST')
        .update({ active: newActiveState })
        .eq('prod_id', serviceToDeactivate.prod_id);

      if (error) throw error;

      setServices(services.map(service => 
        service.prod_id === serviceToDeactivate.prod_id 
          ? { ...service, active: newActiveState } 
          : service
      ));
      
      toast({
        title: newActiveState ? "Service activated" : "Service deactivated",
        description: `Service "${serviceToDeactivate.Services}" has been ${newActiveState ? "activated" : "deactivated"}`,
      });
      
      setOpenDeactivateDialog(false);
    } catch (error) {
      console.error('Error updating service active state:', error);
      toast({
        title: "Error",
        description: "Failed to update the service",
        variant: "destructive",
      });
    }
  };

  const toggleStatus = (service: Service) => {
    setServiceToDeactivate(service);
    setOpenDeactivateDialog(true);
  };

  const handlePriceChange = (value: string) => {
    setServicePrice(value);
    if (priceFirst && discount) {
      // If price changes and we have discount, calculate net payable
      const price = parseFloat(value) || 0;
      const discountValue = parseFloat(discount) || 0;
      const calculatedNetPayable = price * (1 - discountValue / 100);
      setNetPayable(calculatedNetPayable.toFixed(2));
    }
  };

  const handleDiscountChange = (value: string) => {
    setDiscount(value);
    if (priceFirst && servicePrice) {
      // If discount changes and we have price, calculate net payable
      const price = parseFloat(servicePrice) || 0;
      const discountValue = parseFloat(value) || 0;
      const calculatedNetPayable = price * (1 - discountValue / 100);
      setNetPayable(calculatedNetPayable.toFixed(2));
    }
  };

  const handleNetPayableChange = (value: string) => {
    setNetPayable(value);
    if (!priceFirst && servicePrice) {
      // If net payable changes and we have price, calculate discount
      const price = parseFloat(servicePrice) || 0;
      const netPayableValue = parseFloat(value) || 0;
      if (price > 0) {
        const calculatedDiscount = ((price - netPayableValue) / price) * 100;
        setDiscount(calculatedDiscount.toFixed(2));
      }
    }
  };

  const toggleCalculationMode = () => {
    setPriceFirst(!priceFirst);
  };

  const handleSave = async () => {
    try {
      const priceValue = parseFloat(servicePrice);
      const discountValue = parseFloat(discount) || 0;
      const netPayableValue = parseFloat(netPayable) || 0;
      
      if (isNaN(priceValue)) {
        throw new Error("Price must be a valid number");
      }

      const productName = generateProductName();
      
      // Check if the ProductName already exists (for new services or when changing existing service details)
      if (productName) {
        const { data, error } = await supabase
          .from('PriceMST')
          .select('prod_id')
          .eq('ProductName', productName);
          
        if (error) throw error;
        
        if (data && data.length > 0 && (!currentService || data[0].prod_id !== currentService.prod_id)) {
          throw new Error("A service with this combination of Service, Sub-service, and Scheme already exists");
        }
      }

      const serviceData = {
        Services: serviceName,
        Subservice: subService || null,
        Scheme: scheme || null,
        Category: category || null,
        ProductName: productName,
        Description: serviceDescription || null,
        Price: priceValue,
        Discount: discountValue || null,
        NetPayable: netPayableValue || null,
        active: true
      };

      if (isNewService) {
        const { data, error } = await supabase
          .from('PriceMST')
          .insert([serviceData])
          .select();

        if (error) throw error;
        
        if (data && data.length > 0) {
          setServices([...services, data[0]]);
        }
        
        toast({
          title: "Service added",
          description: "New service has been successfully added",
        });
      } else if (currentService) {
        const { error } = await supabase
          .from('PriceMST')
          .update(serviceData)
          .eq('prod_id', currentService.prod_id);

        if (error) throw error;

        setServices(services.map(service => 
          service.prod_id === currentService.prod_id 
            ? { ...service, ...serviceData } 
            : service
        ));
        
        toast({
          title: "Service updated",
          description: "Service has been successfully updated",
        });
      }

      setOpenDialog(false);
    } catch (error) {
      console.error('Error saving service:', error);
      toast({
        title: "Save failed",
        description: error instanceof Error ? error.message : "There was a problem saving the service",
        variant: "destructive"
      });
    }
  };

  return (
    <ProtectedRoute allowedRoles={["admin", "superadmin"]}>
      <DashboardLayout title="Manage Services">
        <Card>
          <CardHeader className="flex flex-col sm:flex-row justify-between items-start sm:items-center space-y-2 sm:space-y-0">
            <CardTitle>Service Management</CardTitle>
            <div className="flex flex-col sm:flex-row items-center gap-2">
              <ExportButton
                data={filteredServices}
                filename="services"
                headers={serviceHeaders}
                buttonText="Export Services"
              />
              <Button onClick={handleAddNew}>
                <Plus className="mr-2 h-4 w-4" /> Add New Service
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="mb-6 grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="relative">
                <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search services..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-8"
                />
              </div>
              <Select
                value={activeFilter}
                onValueChange={setActiveFilter}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Filter by status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Services</SelectItem>
                  <SelectItem value="active">Active Services</SelectItem>
                  <SelectItem value="inactive">Inactive Services</SelectItem>
                </SelectContent>
              </Select>
              <Button 
                variant="outline" 
                onClick={clearFilters}
                className="flex items-center"
              >
                <X className="mr-2 h-4 w-4" />
                Clear Filters
              </Button>
            </div>

            <div className="mb-4 text-sm text-muted-foreground">
              Showing {filteredServices.length} of {services.length} services
            </div>

            {loading ? (
              <div className="flex justify-center p-4">Loading services...</div>
            ) : filteredServices.length === 0 ? (
              <p className="text-muted-foreground py-4 text-center">
                No services match your filters. Try adjusting your search criteria.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Service</TableHead>
                      <TableHead>Product Name</TableHead>
                      <TableHead>Sub-service</TableHead>
                      <TableHead>Scheme</TableHead>
                      <TableHead>Price</TableHead>
                      <TableHead>Discount %</TableHead>
                      <TableHead>Net Payable</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredServices.map((service) => (
                      <TableRow key={service.prod_id}>
                        <TableCell className="font-medium">{service.Services}</TableCell>
                        <TableCell className="max-w-xs truncate">{service.ProductName}</TableCell>
                        <TableCell>{service.Subservice}</TableCell>
                        <TableCell>{service.Scheme}</TableCell>
                        <TableCell>₹{service.Price}</TableCell>
                        <TableCell>{service.Discount}%</TableCell>
                        <TableCell>₹{service.NetPayable}</TableCell>
                        <TableCell>
                          <div className="flex items-center space-x-2">
                            <Switch 
                              checked={service.active} 
                              onCheckedChange={() => toggleStatus(service)}
                            />
                            <span className={service.active ? "text-green-600" : "text-red-600"}>
                              {service.active ? 'Active' : 'Inactive'}
                            </span>
                          </div>
                        </TableCell>
                        <TableCell className="text-right space-x-2">
                          <Button 
                            variant="outline" 
                            size="sm" 
                            onClick={() => handleEdit(service)}
                          >
                            <Edit className="h-4 w-4 mr-1" /> Edit
                          </Button>
                          
                          {isSuperAdmin && (
                            <Button 
                              variant="destructive" 
                              size="sm" 
                              onClick={() => handleDelete(service)}
                            >
                              <Trash2 className="h-4 w-4 mr-1" /> Delete
                            </Button>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>

        <Dialog open={openDialog} onOpenChange={setOpenDialog}>
          <DialogContent className="sm:max-w-[500px] max-h-[90vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>{isNewService ? "Add New Service" : "Edit Service"}</DialogTitle>
              <DialogDescription>
                {isNewService 
                  ? "Add a new service to your catalog." 
                  : "Make changes to the existing service."}
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-4 py-4">
              <div className="grid grid-cols-4 items-center gap-4">
                <Label htmlFor="service-name" className="text-right">
                  Service Name*
                </Label>
                <Input
                  id="service-name"
                  value={serviceName}
                  onChange={(e) => setServiceName(e.target.value)}
                  className="col-span-3"
                />
              </div>
              
              <div className="grid grid-cols-4 items-center gap-4">
                <Label htmlFor="sub-service" className="text-right">
                  Sub-service
                </Label>
                <Input
                  id="sub-service"
                  value={subService}
                  onChange={(e) => setSubService(e.target.value)}
                  className="col-span-3"
                />
              </div>
              
              <div className="grid grid-cols-4 items-center gap-4">
                <Label htmlFor="scheme" className="text-right">
                  Scheme
                </Label>
                <Input
                  id="scheme"
                  value={scheme}
                  onChange={(e) => setScheme(e.target.value)}
                  className="col-span-3"
                />
              </div>
              
              <div className="grid grid-cols-4 items-center gap-4">
                <Label htmlFor="category" className="text-right">
                  Category
                </Label>
                <Input
                  id="category"
                  value={category}
                  onChange={(e) => setCategory(e.target.value)}
                  className="col-span-3"
                />
              </div>
              
              <div className="grid grid-cols-4 items-center gap-4">
                <Label htmlFor="product-name" className="text-right">
                  Product Name
                </Label>
                <Input
                  id="product-name"
                  value={generateProductName()}
                  className="col-span-3 bg-gray-100"
                  disabled
                />
              </div>
              
              <div className="grid grid-cols-4 items-center gap-4">
                <Label htmlFor="service-price" className="text-right">
                  Price (₹)*
                </Label>
                <Input
                  id="service-price"
                  type="number"
                  value={servicePrice}
                  onChange={(e) => handlePriceChange(e.target.value)}
                  className="col-span-3"
                />
              </div>
              
              <div className="grid grid-cols-4 items-center gap-4">
                <div className="text-right flex items-center justify-end">
                  <Label htmlFor="calculation-mode" className="mr-2">
                    Price first
                  </Label>
                  <Switch
                    id="calculation-mode"
                    checked={priceFirst}
                    onCheckedChange={toggleCalculationMode}
                  />
                </div>
                <div className="col-span-3 text-sm text-muted-foreground">
                  {priceFirst 
                    ? "Enter price and discount % to calculate net payable" 
                    : "Enter price and net payable to calculate discount %"}
                </div>
              </div>
              
              <div className="grid grid-cols-4 items-center gap-4">
                <Label htmlFor="discount" className="text-right">
                  Discount %
                </Label>
                <Input
                  id="discount"
                  type="number"
                  value={discount}
                  onChange={(e) => handleDiscountChange(e.target.value)}
                  className="col-span-3"
                />
              </div>
              
              <div className="grid grid-cols-4 items-center gap-4">
                <Label htmlFor="net-payable" className="text-right">
                  Net Payable (₹)
                </Label>
                <Input
                  id="net-payable"
                  type="number"
                  value={netPayable}
                  onChange={(e) => handleNetPayableChange(e.target.value)}
                  className="col-span-3"
                />
              </div>
              
              <div className="grid grid-cols-4 items-center gap-4">
                <Label htmlFor="service-description" className="text-right">
                  Description
                </Label>
                <Textarea
                  id="service-description"
                  value={serviceDescription}
                  onChange={(e) => setServiceDescription(e.target.value)}
                  className="col-span-3"
                  rows={3}
                />
              </div>
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setOpenDialog(false)}>
                Cancel
              </Button>
              <Button 
                type="submit" 
                onClick={handleSave}
                disabled={!serviceName || !servicePrice}
              >
                Save
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        <AlertDialog open={openDeleteDialog} onOpenChange={setOpenDeleteDialog}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Are you absolutely sure?</AlertDialogTitle>
              <AlertDialogDescription>
                This action cannot be undone. This will permanently delete the 
                service and all related data.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction onClick={confirmDelete} className="bg-destructive text-destructive-foreground">
                Delete
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>

        <AlertDialog open={openDeactivateDialog} onOpenChange={setOpenDeactivateDialog}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>
                {serviceToDeactivate?.active ? "Confirm Deactivation" : "Confirm Activation"}
              </AlertDialogTitle>
              <AlertDialogDescription>
                Are you sure you want to {serviceToDeactivate?.active ? "deactivate" : "activate"} this service? 
                {serviceToDeactivate?.active 
                  ? " Deactivated services won't be visible to users."
                  : " Activated services will be visible to users."}
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction onClick={confirmDeactivate}>
                {serviceToDeactivate?.active ? "Deactivate" : "Activate"}
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </DashboardLayout>
    </ProtectedRoute>
  );
};

export default AdminServices;
