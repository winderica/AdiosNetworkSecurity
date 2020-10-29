import { makeStyles } from '@material-ui/core/styles';

export const useStyles = makeStyles(({ transitions, mixins, spacing }) => ({
    drawerPaper: ({ open }) => ({
        position: 'sticky',
        overflowX: 'hidden',
        width: spacing(open ? 30 : 9),
        transition: transitions.create('width', {
            easing: transitions.easing.sharp,
            duration: open ? transitions.duration.enteringScreen : transitions.duration.leavingScreen,
        }),
    }),
    toolbar: {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'flex-end',
        padding: `0 ${spacing(1)}px`,
        ...mixins.toolbar,
    },
    icon: {
        margin: `0 ${spacing(1)}px`
    }
}));
