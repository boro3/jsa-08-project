

                         users (8083)       \
                         /                     \
                        /
  browser -> proxy (80) -- auth (8081)          -   DB
                        \
                         \                      /
                           storage (8082)      /
  
  
  
  /api/v1/auth/... -> auth (8081)
  /api/v1/storage/... -> storage (8082)
  /api/v1/users/... -> users (8083)
  ...
  
  // git bash