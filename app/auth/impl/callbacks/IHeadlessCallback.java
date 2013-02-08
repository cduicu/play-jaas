package auth.impl.callbacks;

import javax.security.auth.callback.Callback;

public interface IHeadlessCallback extends Callback {

    void process();

}
