//==========================================================================
// $Id: IHeadelessCallback.java,v 0.1 Nov 2, 2012 10:00:31 AM cristiand Exp $
// (@) Copyright Sigma Systems (Canada)
// * Based on CVS log
//==========================================================================
package auth.impl.callbacks;

import javax.security.auth.callback.Callback;

/**
 * @version $Revision: $
 * @author $Author: cristiand $
 * @since $Date: Nov 2, 2012 $
 */
public interface IHeadlessCallback extends Callback {

    void process();

}
