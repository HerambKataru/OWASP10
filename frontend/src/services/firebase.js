import { initializeApp, getApps, getApp } from 'firebase/app';
import {
  getAuth,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signOut,
  onAuthStateChanged,
  GoogleAuthProvider,
  signInWithPopup
} from 'firebase/auth';

// Active Firebase Configuration
export const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY || "AIzaSyB5g8P-Kcu3IeL7W2KZjFF75p5MzfU5vu4",
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN || "cve-project-739d4.firebaseapp.com",
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID || "cve-project-739d4",
  storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET || "cve-project-739d4.firebasestorage.app",
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID || "894332952335",
  appId: import.meta.env.VITE_FIREBASE_APP_ID || "1:894332952335:web:3942e74f3e3a2c2a48a87a",
  measurementId: import.meta.env.VITE_FIREBASE_MEASUREMENT_ID || "G-BPR4VY7SXK"
};

// Initialize Firebase App & Auth
const app = !getApps().length ? initializeApp(firebaseConfig) : getApp();
const auth = getAuth(app);
const googleProvider = new GoogleAuthProvider();

export {
  app,
  auth,
  googleProvider,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signOut,
  onAuthStateChanged,
  signInWithPopup
};
