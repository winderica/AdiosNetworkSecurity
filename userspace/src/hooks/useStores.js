import { createContext, useContext } from 'react';

import { stores } from '../stores';

export const useStores = () => useContext(createContext(stores));
