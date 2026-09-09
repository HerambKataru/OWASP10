import { auth } from './firebase';
import {
  getFirestore,
  collection,
  addDoc,
  getDocs,
  query,
  orderBy,
  limit,
  serverTimestamp
} from 'firebase/firestore';

let firestore;
try {
  if (auth && auth.app) {
    firestore = getFirestore(auth.app);
  }
} catch (err) {
  console.warn("Firestore initialization optional fallback:", err);
}

export const syncScanToFirebase = async (scanData) => {
  if (!firestore) return null;
  try {
    const docRef = await addDoc(collection(firestore, "sentinelx_scans"), {
      ...scanData,
      syncedAt: serverTimestamp()
    });
    return docRef.id;
  } catch (error) {
    console.warn("Firebase Firestore sync:", error.message);
    return null;
  }
};

export const syncFindingToFirebase = async (scanId, findingData) => {
  if (!firestore) return null;
  try {
    const docRef = await addDoc(collection(firestore, "sentinelx_findings"), {
      scanId,
      ...findingData,
      syncedAt: serverTimestamp()
    });
    return docRef.id;
  } catch (error) {
    console.warn("Firebase Firestore finding sync:", error.message);
    return null;
  }
};

export { firestore };
