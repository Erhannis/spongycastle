#!/bin/bash 

# no further use for remaining crypto stuff

rm -Rf crypto

# Package rename org.spongycastle.to org.spongycastle
    
find -name.spongycastle.| xargs rename s.spongycastle.spongycastle/
find bc* -type f | xargs sed -i s.spongycastle.spongycastle/g

# BC to SC for provider name
    
find bc* -type f | xargs sed -i s/\"BC\"/\"SC\"/g

# Rename 'bc' artifacts to 'sc'
    
rename s/^bc/sc/ *
find -name 'pom.xml' | xargs sed -i s/\>bc/\>sc/g

# Rename maven artifact 'names' to use Spongy rather than Bouncy

find -name 'pom.xml' | xargs sed -i s/\>Bouncy/\>Spongy/g
