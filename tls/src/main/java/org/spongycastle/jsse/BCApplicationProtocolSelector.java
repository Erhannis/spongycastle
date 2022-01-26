package org.spongycastle.jsse;

import java.util.List;

public interface BCApplicationProtocolSelector<T>
{
    String select(T transport, List<String> protocols);
}
