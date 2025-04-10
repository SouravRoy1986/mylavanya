
import React, { useState } from "react";
import { TableRow, TableCell } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Pencil, Trash2 } from "lucide-react";
import { Booking } from "@/hooks/useBookings";
import { BookingStatusSelect } from "./BookingStatusSelect";
import { ArtistAssignmentSelect } from "./ArtistAssignmentSelect";
import { JobScheduleCell } from "./JobScheduleCell";
import { StatusBadge } from "@/components/ui/status-badge";
import { useAuth } from "@/context/AuthContext";

interface JobTableRowProps {
  booking: Booking;
  onEditClick: (booking: Booking) => void;
  onDeleteJob?: (booking: Booking) => Promise<void>;
  isEditingDisabled: boolean;
  handleStatusChange: (booking: Booking, newStatus: string) => Promise<void>;
  handleArtistAssignment: (booking: Booking, artistId: number) => Promise<void>;
  onScheduleChange?: (booking: Booking, date: string, time: string) => Promise<void>;
  statusOptions: {status_code: string; status_name: string}[];
  artists: {ArtistId: number; ArtistFirstName: string; ArtistLastName: string}[];
  showDeleteButton: boolean;
  showActions?: boolean;
}

export const JobTableRow = ({
  booking,
  onEditClick,
  onDeleteJob,
  isEditingDisabled,
  handleStatusChange,
  handleArtistAssignment,
  onScheduleChange,
  statusOptions,
  artists,
  showDeleteButton,
  showActions = true
}: JobTableRowProps) => {
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);
  const [isAssigningArtist, setIsAssigningArtist] = useState(false);
  const [isUpdatingSchedule, setIsUpdatingSchedule] = useState(false);
  const { user } = useAuth();
  const isMember = user?.role === 'member';
  const isAdmin = user?.role === 'admin' || user?.role === 'superadmin' || user?.role === 'controller';
  const isArtist = user?.role === 'artist';

  const handleStatusChangeWrapper = async (newStatus: string) => {
    if (isUpdatingStatus) return;
    
    setIsUpdatingStatus(true);
    try {
      await handleStatusChange(booking, newStatus);
    } finally {
      setIsUpdatingStatus(false);
    }
  };

  // Handle artist assignment with correct parameter order
  const handleArtistAssignmentWrapper = async (artistId: number) => {
    if (isAssigningArtist) return;
    
    setIsAssigningArtist(true);
    try {
      await handleArtistAssignment(booking, artistId);
    } finally {
      setIsAssigningArtist(false);
    }
  };

  const handleScheduleChangeWrapper = async (date: string, time: string) => {
    if (isUpdatingSchedule || !onScheduleChange) return;
    
    setIsUpdatingSchedule(true);
    try {
      await onScheduleChange(booking, date, time);
    } finally {
      setIsUpdatingSchedule(false);
    }
  };

  // Find artist name for display
  const getArtistName = () => {
    if (!booking.ArtistId) return 'Unassigned';
    const artist = artists.find(a => a.ArtistId === Number(booking.ArtistId));
    return artist ? 
      `${artist.ArtistFirstName || ''} ${artist.ArtistLastName || ''}`.trim() || `Artist #${artist.ArtistId}` 
      : booking.Assignedto || 'Assigned';
  };

  return (
    <TableRow>
      <TableCell className="font-medium">{booking.jobno || 'N/A'}</TableCell>
      <TableCell>
        {booking.ServiceName}{booking.SubService ? ` - ${booking.SubService}` : ''}
        {booking.ProductName && <div className="text-xs text-muted-foreground mt-1">{booking.ProductName} x {booking.Qty || 1}</div>}
      </TableCell>

      <TableCell>
        {/* Show schedule data for all users, but JobScheduleCell with edit for admins only */}
        {isAdmin && !isArtist ? (
          <JobScheduleCell 
            booking={booking}
            isEditingDisabled={isEditingDisabled}
            onScheduleChange={handleScheduleChangeWrapper}
            isUpdating={isUpdatingSchedule}
          />
        ) : (
          <div>
            <div className="flex items-center">
              <span className="text-sm">{booking.Booking_date}</span>
            </div>
            <div className="flex items-center mt-1">
              <span className="text-sm">{booking.booking_time}</span>
            </div>
          </div>
        )}
      </TableCell>

      <TableCell>
        {/* Show status badge for all users */}
        <StatusBadge status={booking.Status || 'pending'} />
        
        {/* Only show dropdown for admins (hidden by default) */}
        {isAdmin && false && (
          <BookingStatusSelect 
            currentStatus={booking.Status || 'pending'} 
            statusOptions={statusOptions} 
            onStatusChange={handleStatusChangeWrapper}
            isDisabled={isEditingDisabled || isUpdatingStatus}
          />
        )}
      </TableCell>
      
      <TableCell>
        {/* Show assigned artist name for all users */}
        {getArtistName()}
        
        {/* Only show artist assignment dropdown for admins (hidden by default) */}
        {isAdmin && false && (
          <ArtistAssignmentSelect 
            booking={booking}
            artists={artists}
            onArtistAssignment={handleArtistAssignmentWrapper}
            isDisabled={isEditingDisabled || isAssigningArtist}
          />
        )}
      </TableCell>
      
      {/* Only show actions column for admins */}
      {showActions && isAdmin && (
        <TableCell>
          <div className="flex gap-2">
            <Button
              variant="ghost"
              size="icon"
              onClick={() => onEditClick(booking)}
              disabled={isEditingDisabled}
            >
              <Pencil className="h-4 w-4" />
            </Button>
            
            {onDeleteJob && showDeleteButton && (
              <Button
                variant="ghost"
                size="icon"
                onClick={() => onDeleteJob && onDeleteJob(booking)}
                disabled={isEditingDisabled}
              >
                <Trash2 className="h-4 w-4 text-destructive" />
              </Button>
            )}
          </div>
        </TableCell>
      )}
      
      {/* Hide actions completely for members and artists */}
      {showActions && !isAdmin && (
        <TableCell>
          <div className="text-xs text-muted-foreground">
            {isMember ? "View only" : isArtist ? "Assigned to you" : ""}
          </div>
        </TableCell>
      )}
    </TableRow>
  );
};
