
// Sample testimonial data for the testimonials carousel component
// This can be edited directly or replaced with data from an API or CMS

export interface Testimonial {
  id: number;
  name: string;
  role: string;
  content: string;
  rating: number;
  image: string;
}

export const testimonials: Testimonial[] = [
  {
    id: 1,
    name: "Shreyashi Sur",
    role: "Bride",
    content: "I achieved the exact desired look thanks to this artist, who was truly exceptional and displayed such thoughtful understanding. Without a doubt, I will recommend Lavanya to everyone I know.",
    rating: 5,
    // Use Unsplash images for better quality testimonial photos
    image: "/images/testimonials/img1.jpg"
  },
  {
    id: 2,
    name: "Rima Samanta",
    role: "Party Freak",
    content: "The MUA was right on time. I told him to give me a classy look, and it was right on the money. I was the star of the party. Thank you, Lavanya... ",
    rating: 5,
    image: "/images/testimonials/img2.jpg"
  },
  {
    id: 3,
    name: "Priyanka Ghosh",
    role: "Nail Art",
    content: "Booked for my birthday party. The hairstylist was creative and gave me exactly what I wanted. The team was punctual and professional.",
    rating: 4,
    image: "/images/testimonials/img3.jpg"
  },
  {
    id: 4,
    name: "Meghna Roy",
    role: "Frizzy Hair Treatment",
    content: "I used to have a frizzy hair problem from childhood. I had too many treatments and visited so many therapists. Now I don't think I need to visit other therapists after getting in touch with Lavanya.",
    rating: 4,
    image: "/images/testimonials/img4.jpg"
  },
  {
    id: 5,
    name: "Mainak Bhattacharya",
    role: "Facial",
    content: "My friend recommended Lavanya to me. First of all, I didn't have that much faith in Lavanya but after the service I got, it left me speechless. Especially the massage was so amazing. Thank you, Lavanya.",
    rating: 4,
    image: "/images/testimonials/img5.jpg"
  },
  {
    id: 6,
    name: "Moumita Maity",
    role: "Bride",
    content: "I got the desired look I wanted. The artist was truly amazing and so understanding. I will surely recommend Lavanya to others.",
    rating: 4.2,
    image: "/images/testimonials/img6.jpg"
  },
  {
    id: 7,
    name: "Bipasa Das",
    role: "Party Freak",
    content: "The MUA was right on time. I told him to give me a classy look, and it was right on the money. I was the star of the party. Thank you, Lavanya",
    rating: 4.4,
    image: "/images/testimonials/img7.jpg"
  },
  {
    id: 8,
    name: "Anjali Kumari Choudhuri",
    role: "Nail Art",
    content: "My Nail Artist cancelled my appointment of the last moment. Then I found Lavanya from Facebook. Thank God I found them. They saved my day.",
    rating: 4.1,
    image: "/images/testimonials/img8.jpg"
  },
  {
    id: 9,
    name: "Jahanara Khatun",
    role: "Mehendi",
    content: "I had a sudden plan and didn’t know where to get my Mehendi designed. Then I saw Lavanya on Facebook. I booked with hesitation. But it turned out so great.  Thank you, Lavanya, for the masterclass design.",
    rating: 4.5,
    image: "/images/testimonials/img9.jpg"
  },
  {
    id: 10,
    name: "Risha Mashi",
    role: "Mehendi",
    content: "Yes, the spa was so relaxing. I felt like I was having a hair treatment",
    rating: 4,
    image: "/images/testimonials/img10.jpg"
  },
];

/*
  INSTRUCTIONS FOR CUSTOMIZING TESTIMONIALS:
  
  1. To edit testimonials, simply update the testimonials array above
  2. For each testimonial, you can modify:
     - name: The person's name
     - role: Their role or title
     - content: The testimonial text
     - rating: A number from 1-5
     - image: URL to their profile photo (recommended size: 256x256)
  
  3. To add a new testimonial, copy an existing object and change the values
     Make sure to give it a unique ID
  
  Example:
  {
    id: 4,
    name: "Alex Wong",
    role: "Regular Client",
    content: "I've been using Lavanya's services for years. Always satisfied!",
    rating: 5,
    image: "https://example.com/alex-photo.jpg"
  }
*/
