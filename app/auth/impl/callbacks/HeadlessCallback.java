package auth.impl.callbacks;

import javax.security.auth.callback.Callback;

import play.mvc.Http;

public abstract class HeadlessCallback implements Callback {

    protected Http.Context ctx;

    /**
     * Processes the information from the HTTP context
     *
     * @param ctx
     */
    public void process(Http.Context ctx) {
        this.ctx = ctx;
        process();
    }

    public abstract void process();

    /**
     * Retrieves the original context of the request.
     * @return
     */
    public Http.Context getOriginalContext() {
        return ctx;
    }

    public Http.Request getOriginalRequest() {
        return ctx.request();
    }

}
